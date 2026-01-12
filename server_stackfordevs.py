from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.cors import CORSMiddleware
import os
import logging
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Literal, Dict
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import random
import requests
import secrets
import hashlib

app = FastAPI(title="Ardito EIP API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30

# StackForDevs JWT validation
STACKFORDEVS_PROJECT_ID = os.getenv("STACKFORDEVS_PROJECT_ID", "c65fa251-2dd5-40a0-ae10-14a9159a4999")
STACKFORDEVS_JWKS_URL = f"https://auth.stackfordevs.com/projects/{STACKFORDEVS_PROJECT_ID}/.well-known/jwks.json"
jwks_cache = None
jwks_cache_time = None

# In-memory storage for users and refresh tokens
users_store: Dict[str, dict] = {}
refresh_tokens_store: Dict[str, dict] = {}

def get_jwks():
    global jwks_cache, jwks_cache_time
    now = datetime.now(timezone.utc)

    # Cache JWKS for 1 hour
    if jwks_cache and jwks_cache_time and (now - jwks_cache_time).seconds < 3600:
        return jwks_cache

    try:
        response = requests.get(STACKFORDEVS_JWKS_URL, timeout=5)
        response.raise_for_status()
        jwks_cache = response.json()
        jwks_cache_time = now
        return jwks_cache
    except Exception as e:
        logging.error(f"Failed to fetch JWKS: {e}")
        if jwks_cache:  # Return cached version if fetch fails
            return jwks_cache
        raise HTTPException(status_code=500, detail="Authentication service unavailable")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    # Try our own JWT tokens first (HS256)
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        # Check if it's an access token
        if payload.get("type") == "access":
            user_id = payload.get('sub')
            email = payload.get('email')

            if not user_id:
                raise HTTPException(status_code=401, detail="Invalid token payload")

            # Get user from store if available
            user = users_store.get(user_id)
            if user:
                return {
                    "id": user["id"],
                    "email": user["email"],
                    "name": user["name"],
                    "role": user.get("role", "sponsor")
                }

            # Fallback to token data
            return {
                "id": user_id,
                "email": email,
                "name": email.split('@')[0],
                "role": "sponsor"
            }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        # If our token validation fails, try StackForDevs token validation
        pass

    # Try StackForDevs JWT validation (RS256 with JWKS)
    try:
        # Decode without verification first to get the header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')

        # Get JWKS
        jwks = get_jwks()

        # Find the key with matching kid
        rsa_key = None
        for key in jwks.get('keys', []):
            if key['kid'] == kid:
                rsa_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
                break

        if not rsa_key:
            raise HTTPException(status_code=401, detail="Invalid token key")

        # Verify and decode token
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=['RS256'],
            options={"verify_aud": False}  # StackForDevs tokens don't have aud
        )

        # Extract user info from token
        user_id = payload.get('sub')
        email = payload.get('email')

        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        # Return user object
        return {
            "id": user_id,
            "email": email,
            "name": email.split('@')[0],  # Use email prefix as name
            "role": "sponsor"
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        logging.error(f"Token validation error: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed")

# ==================== AUTH HELPERS ====================

def hash_password(password: str) -> str:
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return hash_password(plain_password) == hashed_password

def create_access_token(user_id: str, email: str) -> str:
    """Create a JWT access token"""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "email": email,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def create_refresh_token(user_id: str) -> str:
    """Create a JWT refresh token"""
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    token_id = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": token_id,
        "type": "refresh"
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    # Store refresh token
    refresh_tokens_store[token_id] = {
        "user_id": user_id,
        "expires_at": expire.isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    return token

def verify_refresh_token(token: str) -> Optional[str]:
    """Verify a refresh token and return user_id if valid"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        if payload.get("type") != "refresh":
            return None

        token_id = payload.get("jti")
        user_id = payload.get("sub")

        # Check if token exists in store
        if token_id not in refresh_tokens_store:
            return None

        return user_id
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def revoke_refresh_token(token: str):
    """Revoke a refresh token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_exp": False})
        token_id = payload.get("jti")
        if token_id and token_id in refresh_tokens_store:
            del refresh_tokens_store[token_id]
    except:
        pass

# ==================== AUTH MODELS ====================

class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: Optional[str] = None
    company: Optional[str] = None

class RefreshRequest(BaseModel):
    refreshToken: str

class AuthResponse(BaseModel):
    accessToken: str
    refreshToken: str
    user: dict

# ==================== MODELS ====================

EmotionType = Literal["euphoria", "tension", "frustration", "nostalgia", "pride", "anxiety", "disappointment"]
CampaignStatus = Literal["draft", "scheduled", "active", "paused", "completed"]
ActivationChannel = Literal["stadium", "mobile", "social", "broadcast"]

class Team(BaseModel):
    id: str
    name: str
    logo: str
    hashtag: str
    conference: str

class Game(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    home_team: Team
    away_team: Team
    start_time: str
    status: Literal["scheduled", "live", "completed"]
    score_home: int = 0
    score_away: int = 0
    venue: str = ""
    attendance: int = 0
    quarter: str = ""
    time_remaining: str = ""

class EmotionData(BaseModel):
    timestamp: str
    euphoria: float = 0
    tension: float = 0
    frustration: float = 0
    nostalgia: float = 0
    pride: float = 0
    anxiety: float = 0
    disappointment: float = 0
    dominant_emotion: str = "tension"
    confidence: float = 0
    post_count: int = 0

class CampaignCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    objective: Literal["awareness", "engagement", "conversions"] = "awareness"
    total_budget: float
    daily_cap: Optional[float] = None
    start_date: str
    end_date: str
    target_emotions: List[EmotionType] = []
    schools: List[str] = []
    channels: List[ActivationChannel] = ["stadium", "mobile"]

class Campaign(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    user_id: str
    name: str
    description: str = ""
    objective: str = "awareness"
    status: CampaignStatus = "draft"
    total_budget: float
    daily_cap: float
    spent: float = 0
    start_date: str
    end_date: str
    target_emotions: List[str] = []
    schools: List[str] = []
    channels: List[str] = []
    impressions: int = 0
    engagements: int = 0
    engagement_rate: float = 0
    roi: float = 0
    created_at: str

class School(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    name: str
    logo: str
    conference: str
    mascot: str
    colors: List[str]

class Activation(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    campaign_id: str
    game_id: str
    emotion_trigger: str
    channels: List[str]
    timestamp: str
    impressions: int
    engagements: int
    engagement_rate: float
    status: Literal["success", "in_progress", "failed"]

class DashboardMetrics(BaseModel):
    active_campaigns: int
    running_campaigns: int
    scheduled_campaigns: int
    live_games_today: int
    live_now: int
    starting_soon: int
    impressions_24h: int
    engagement_rate: float
    roi_this_week: float
    attributed_revenue: float

# ==================== MOCK DATA ====================

TEAMS = [
    Team(id="1", name="Alabama Crimson Tide", logo="https://upload.wikimedia.org/wikipedia/commons/1/1b/Alabama_Crimson_Tide_logo.svg", hashtag="#RollTide", conference="SEC"),
    Team(id="2", name="Georgia Bulldogs", logo="https://upload.wikimedia.org/wikipedia/commons/8/80/Georgia_Bulldogs_logo.svg", hashtag="#GoDawgs", conference="SEC"),
    Team(id="3", name="Ohio State Buckeyes", logo="https://upload.wikimedia.org/wikipedia/commons/c/c1/Ohio_State_Buckeyes_logo.svg", hashtag="#GoBucks", conference="Big Ten"),
    Team(id="4", name="Michigan Wolverines", logo="https://upload.wikimedia.org/wikipedia/commons/f/fb/Michigan_Wolverines_logo.svg", hashtag="#GoBlue", conference="Big Ten"),
    Team(id="5", name="Texas Longhorns", logo="https://upload.wikimedia.org/wikipedia/commons/8/8d/Texas_Longhorns_logo.svg", hashtag="#HookEm", conference="SEC"),
    Team(id="6", name="USC Trojans", logo="https://upload.wikimedia.org/wikipedia/commons/9/94/USC_Trojans_logo.svg", hashtag="#FightOn", conference="Big Ten"),
]

SCHOOLS = [
    School(id="1", name="University of Alabama", logo="https://upload.wikimedia.org/wikipedia/commons/1/1b/Alabama_Crimson_Tide_logo.svg", conference="SEC", mascot="Big Al", colors=["#9E1B32", "#828A8F"]),
    School(id="2", name="University of Georgia", logo="https://upload.wikimedia.org/wikipedia/commons/8/80/Georgia_Bulldogs_logo.svg", conference="SEC", mascot="Uga", colors=["#BA0C2F", "#000000"]),
    School(id="3", name="Ohio State University", logo="https://upload.wikimedia.org/wikipedia/commons/c/c1/Ohio_State_Buckeyes_logo.svg", conference="Big Ten", mascot="Brutus Buckeye", colors=["#BB0000", "#666666"]),
    School(id="4", name="University of Michigan", logo="https://upload.wikimedia.org/wikipedia/commons/f/fb/Michigan_Wolverines_logo.svg", conference="Big Ten", mascot="Wolverine", colors=["#00274C", "#FFCB05"]),
    School(id="5", name="University of Texas", logo="https://upload.wikimedia.org/wikipedia/commons/8/8d/Texas_Longhorns_logo.svg", conference="SEC", mascot="Bevo", colors=["#BF5700", "#FFFFFF"]),
    School(id="6", name="USC", logo="https://upload.wikimedia.org/wikipedia/commons/9/94/USC_Trojans_logo.svg", conference="Big Ten", mascot="Traveler", colors=["#990000", "#FFC72C"]),
]

# In-memory storage for campaigns
campaigns_store = {}

def generate_mock_games():
    now = datetime.now(timezone.utc)
    return [
        Game(
            id="game-1",
            home_team=TEAMS[0],
            away_team=TEAMS[1],
            start_time=(now - timedelta(hours=1)).isoformat(),
            status="live",
            score_home=21,
            score_away=17,
            venue="Bryant-Denny Stadium",
            attendance=101821,
            quarter="3rd Quarter",
            time_remaining="8:42"
        ),
        Game(
            id="game-2",
            home_team=TEAMS[2],
            away_team=TEAMS[3],
            start_time=(now - timedelta(minutes=30)).isoformat(),
            status="live",
            score_home=14,
            score_away=14,
            venue="Ohio Stadium",
            attendance=102780,
            quarter="2nd Quarter",
            time_remaining="3:15"
        ),
        Game(
            id="game-3",
            home_team=TEAMS[4],
            away_team=TEAMS[5],
            start_time=(now + timedelta(hours=2)).isoformat(),
            status="scheduled",
            score_home=0,
            score_away=0,
            venue="Darrell K Royal Stadium",
            attendance=0,
            quarter="",
            time_remaining=""
        ),
    ]

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/register", response_model=AuthResponse)
async def register(request: RegisterRequest):
    """Register a new user"""
    # Check if user already exists
    if any(u["email"] == request.email for u in users_store.values()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Validate password (must have at least one uppercase letter)
    if not any(c.isupper() for c in request.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must include at least one uppercase letter"
        )

    # Create user
    user_id = str(uuid.uuid4())
    user = {
        "id": user_id,
        "email": request.email,
        "name": request.name or request.email.split('@')[0],
        "company": request.company,
        "password_hash": hash_password(request.password),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "role": "sponsor"
    }
    users_store[user_id] = user

    # Generate tokens
    access_token = create_access_token(user_id, request.email)
    refresh_token = create_refresh_token(user_id)

    # Return user without password
    user_data = {k: v for k, v in user.items() if k != "password_hash"}

    return AuthResponse(
        accessToken=access_token,
        refreshToken=refresh_token,
        user=user_data
    )

@api_router.post("/auth/login", response_model=AuthResponse)
async def login(request: LoginRequest):
    """Login a user"""
    # Find user by email
    user = None
    for u in users_store.values():
        if u["email"] == request.email:
            user = u
            break

    if not user or not verify_password(request.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Generate tokens
    access_token = create_access_token(user["id"], user["email"])
    refresh_token = create_refresh_token(user["id"])

    # Return user without password
    user_data = {k: v for k, v in user.items() if k != "password_hash"}

    return AuthResponse(
        accessToken=access_token,
        refreshToken=refresh_token,
        user=user_data
    )

@api_router.post("/auth/refresh")
async def refresh(request: RefreshRequest):
    """Refresh access token using refresh token"""
    user_id = verify_refresh_token(request.refreshToken)

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    # Get user
    user = users_store.get(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    # Revoke old refresh token
    revoke_refresh_token(request.refreshToken)

    # Generate new tokens
    access_token = create_access_token(user["id"], user["email"])
    new_refresh_token = create_refresh_token(user["id"])

    return {
        "accessToken": access_token,
        "refreshToken": new_refresh_token
    }

@api_router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current user info"""
    user_id = current_user["id"]
    user = users_store.get(user_id)

    if user:
        # Return user from store without password
        return {"user": {k: v for k, v in user.items() if k != "password_hash"}}

    # If not in store (e.g., StackForDevs token), return the current_user from token
    return {"user": current_user}

# ==================== DATA ROUTES ====================

@api_router.get("/games/live", response_model=List[Game])
async def get_live_games():
    return generate_mock_games()

@api_router.get("/games/{game_id}", response_model=Game)
async def get_game(game_id: str):
    games = generate_mock_games()
    for game in games:
        if game.id == game_id:
            return game
    raise HTTPException(status_code=404, detail="Game not found")

@api_router.get("/games/{game_id}/emotions")
async def get_game_emotions(game_id: str):
    now = datetime.now(timezone.utc)
    emotions = []
    for i in range(30):
        timestamp = (now - timedelta(minutes=29-i)).isoformat()
        base_tension = 50 + random.randint(-20, 30)
        emotions.append(EmotionData(
            timestamp=timestamp,
            euphoria=random.randint(20, 80),
            tension=base_tension,
            frustration=random.randint(10, 40),
            nostalgia=random.randint(5, 25),
            pride=random.randint(30, 70),
            anxiety=random.randint(20, 50),
            disappointment=random.randint(5, 30),
            dominant_emotion="tension" if base_tension > 60 else "euphoria",
            confidence=random.randint(70, 95),
            post_count=random.randint(500, 3000)
        ))
    return emotions

@api_router.get("/campaigns", response_model=List[Campaign])
async def get_campaigns(
    status: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    user_campaigns = [c for c in campaigns_store.values() if c["user_id"] == current_user["id"]]
    if status and status != "all":
        user_campaigns = [c for c in user_campaigns if c["status"] == status]
    return user_campaigns

@api_router.post("/campaigns", response_model=Campaign)
async def create_campaign(
    campaign_data: CampaignCreate,
    current_user: dict = Depends(get_current_user)
):
    campaign_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    campaign_doc = {
        "id": campaign_id,
        "user_id": current_user["id"],
        "name": campaign_data.name,
        "description": campaign_data.description,
        "objective": campaign_data.objective,
        "status": "draft",
        "total_budget": campaign_data.total_budget,
        "daily_cap": campaign_data.daily_cap or campaign_data.total_budget / 30,
        "spent": 0,
        "start_date": campaign_data.start_date,
        "end_date": campaign_data.end_date,
        "target_emotions": campaign_data.target_emotions,
        "schools": campaign_data.schools,
        "channels": campaign_data.channels,
        "impressions": 0,
        "engagements": 0,
        "engagement_rate": 0,
        "roi": 0,
        "created_at": now
    }
    campaigns_store[campaign_id] = campaign_doc
    return Campaign(**campaign_doc)

@api_router.get("/campaigns/{campaign_id}", response_model=Campaign)
async def get_campaign(
    campaign_id: str,
    current_user: dict = Depends(get_current_user)
):
    campaign = campaigns_store.get(campaign_id)
    if not campaign or campaign["user_id"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return Campaign(**campaign)

@api_router.put("/campaigns/{campaign_id}/status")
async def update_campaign_status(
    campaign_id: str,
    status: CampaignStatus,
    current_user: dict = Depends(get_current_user)
):
    campaign = campaigns_store.get(campaign_id)
    if not campaign or campaign["user_id"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="Campaign not found")
    campaign["status"] = status
    return {"message": "Status updated", "status": status}

@api_router.delete("/campaigns/{campaign_id}")
async def delete_campaign(
    campaign_id: str,
    current_user: dict = Depends(get_current_user)
):
    campaign = campaigns_store.get(campaign_id)
    if not campaign or campaign["user_id"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="Campaign not found")
    del campaigns_store[campaign_id]
    return {"message": "Campaign deleted"}

@api_router.get("/schools", response_model=List[School])
async def get_schools(conference: Optional[str] = None):
    if conference:
        return [s for s in SCHOOLS if s.conference == conference]
    return SCHOOLS

@api_router.get("/analytics/dashboard", response_model=DashboardMetrics)
async def get_dashboard_metrics(current_user: dict = Depends(get_current_user)):
    user_campaigns = [c for c in campaigns_store.values() if c["user_id"] == current_user["id"]]
    total = len(user_campaigns)
    active = len([c for c in user_campaigns if c["status"] == "active"])
    scheduled = len([c for c in user_campaigns if c["status"] == "scheduled"])

    return DashboardMetrics(
        active_campaigns=total,
        running_campaigns=active,
        scheduled_campaigns=scheduled,
        live_games_today=5,
        live_now=2,
        starting_soon=3,
        impressions_24h=2400000,
        engagement_rate=38.2,
        roi_this_week=8.5,
        attributed_revenue=450000
    )

@api_router.get("/analytics/activations", response_model=List[Activation])
async def get_recent_activations(current_user: dict = Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    activations = []
    emotions = ["euphoria", "tension", "pride", "frustration", "anxiety"]
    channels_options = [["stadium", "mobile"], ["mobile", "social"], ["stadium", "mobile", "social"], ["broadcast", "mobile"]]

    for i in range(10):
        activations.append(Activation(
            id=str(uuid.uuid4()),
            campaign_id=f"campaign-{random.randint(1, 5)}",
            game_id=f"game-{random.randint(1, 3)}",
            emotion_trigger=random.choice(emotions),
            channels=random.choice(channels_options),
            timestamp=(now - timedelta(minutes=i*5)).isoformat(),
            impressions=random.randint(50000, 200000),
            engagements=random.randint(15000, 80000),
            engagement_rate=random.uniform(28, 45),
            status="success"
        ))
    return activations

@api_router.get("/analytics/emotions")
async def get_emotion_distribution():
    return {
        "euphoria": 35,
        "tension": 25,
        "pride": 18,
        "frustration": 12,
        "anxiety": 6,
        "nostalgia": 3,
        "disappointment": 1
    }

@api_router.get("/")
async def root():
    return {"message": "Ardito EIP API", "version": "1.0.0"}

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],  # Configure this properly for production
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
