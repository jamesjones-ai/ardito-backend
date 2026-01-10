from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional, Literal
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt
import random

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Settings
JWT_SECRET = os.environ['JWT_SECRET']
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

app = FastAPI(title="Ardito EIP API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# ==================== MODELS ====================

# Emotion Types
EmotionType = Literal["euphoria", "tension", "frustration", "nostalgia", "pride", "anxiety", "disappointment"]
CampaignStatus = Literal["draft", "scheduled", "active", "paused", "completed"]
ActivationChannel = Literal["stadium", "mobile", "social", "broadcast"]

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str
    company: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    email: str
    name: str
    company: Optional[str] = None
    role: str = "sponsor"
    created_at: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

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

# ==================== AUTH HELPERS ====================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str) -> str:
    payload = {
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = await db.users.find_one({"id": user_id}, {"_id": 0, "password": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user_data: UserCreate):
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = str(uuid.uuid4())
    user_doc = {
        "id": user_id,
        "email": user_data.email,
        "password": hash_password(user_data.password),
        "name": user_data.name,
        "company": user_data.company,
        "role": "sponsor",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.users.insert_one(user_doc)
    
    token = create_token(user_id)
    user_response = UserResponse(
        id=user_id,
        email=user_data.email,
        name=user_data.name,
        company=user_data.company,
        role="sponsor",
        created_at=user_doc["created_at"]
    )
    return TokenResponse(access_token=token, user=user_response)

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(login_data: UserLogin):
    user = await db.users.find_one({"email": login_data.email})
    if not user or not verify_password(login_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user["id"])
    user_response = UserResponse(
        id=user["id"],
        email=user["email"],
        name=user["name"],
        company=user.get("company"),
        role=user.get("role", "sponsor"),
        created_at=user["created_at"]
    )
    return TokenResponse(access_token=token, user=user_response)

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(**current_user)

# ==================== GAMES ROUTES ====================

# Mock team data
TEAMS = [
    Team(id="1", name="Alabama Crimson Tide", logo="https://upload.wikimedia.org/wikipedia/commons/1/1b/Alabama_Crimson_Tide_logo.svg", hashtag="#RollTide", conference="SEC"),
    Team(id="2", name="Georgia Bulldogs", logo="https://upload.wikimedia.org/wikipedia/commons/8/80/Georgia_Bulldogs_logo.svg", hashtag="#GoDawgs", conference="SEC"),
    Team(id="3", name="Ohio State Buckeyes", logo="https://upload.wikimedia.org/wikipedia/commons/c/c1/Ohio_State_Buckeyes_logo.svg", hashtag="#GoBucks", conference="Big Ten"),
    Team(id="4", name="Michigan Wolverines", logo="https://upload.wikimedia.org/wikipedia/commons/f/fb/Michigan_Wolverines_logo.svg", hashtag="#GoBlue", conference="Big Ten"),
    Team(id="5", name="Texas Longhorns", logo="https://upload.wikimedia.org/wikipedia/commons/8/8d/Texas_Longhorns_logo.svg", hashtag="#HookEm", conference="SEC"),
    Team(id="6", name="USC Trojans", logo="https://upload.wikimedia.org/wikipedia/commons/9/94/USC_Trojans_logo.svg", hashtag="#FightOn", conference="Big Ten"),
]

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
    """Generate mock real-time emotion data for a game"""
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

# ==================== CAMPAIGNS ROUTES ====================

@api_router.get("/campaigns", response_model=List[Campaign])
async def get_campaigns(
    status: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    query = {"user_id": current_user["id"]}
    if status and status != "all":
        query["status"] = status
    
    campaigns = await db.campaigns.find(query, {"_id": 0}).to_list(100)
    return campaigns

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
    await db.campaigns.insert_one(campaign_doc)
    return Campaign(**campaign_doc)

@api_router.get("/campaigns/{campaign_id}", response_model=Campaign)
async def get_campaign(
    campaign_id: str,
    current_user: dict = Depends(get_current_user)
):
    campaign = await db.campaigns.find_one(
        {"id": campaign_id, "user_id": current_user["id"]},
        {"_id": 0}
    )
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return Campaign(**campaign)

@api_router.put("/campaigns/{campaign_id}/status")
async def update_campaign_status(
    campaign_id: str,
    status: CampaignStatus,
    current_user: dict = Depends(get_current_user)
):
    result = await db.campaigns.update_one(
        {"id": campaign_id, "user_id": current_user["id"]},
        {"$set": {"status": status}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return {"message": "Status updated", "status": status}

@api_router.delete("/campaigns/{campaign_id}")
async def delete_campaign(
    campaign_id: str,
    current_user: dict = Depends(get_current_user)
):
    result = await db.campaigns.delete_one(
        {"id": campaign_id, "user_id": current_user["id"]}
    )
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return {"message": "Campaign deleted"}

# ==================== SCHOOLS ROUTES ====================

SCHOOLS = [
    School(id="1", name="University of Alabama", logo="https://upload.wikimedia.org/wikipedia/commons/1/1b/Alabama_Crimson_Tide_logo.svg", conference="SEC", mascot="Big Al", colors=["#9E1B32", "#828A8F"]),
    School(id="2", name="University of Georgia", logo="https://upload.wikimedia.org/wikipedia/commons/8/80/Georgia_Bulldogs_logo.svg", conference="SEC", mascot="Uga", colors=["#BA0C2F", "#000000"]),
    School(id="3", name="Ohio State University", logo="https://upload.wikimedia.org/wikipedia/commons/c/c1/Ohio_State_Buckeyes_logo.svg", conference="Big Ten", mascot="Brutus Buckeye", colors=["#BB0000", "#666666"]),
    School(id="4", name="University of Michigan", logo="https://upload.wikimedia.org/wikipedia/commons/f/fb/Michigan_Wolverines_logo.svg", conference="Big Ten", mascot="Wolverine", colors=["#00274C", "#FFCB05"]),
    School(id="5", name="University of Texas", logo="https://upload.wikimedia.org/wikipedia/commons/8/8d/Texas_Longhorns_logo.svg", conference="SEC", mascot="Bevo", colors=["#BF5700", "#FFFFFF"]),
    School(id="6", name="USC", logo="https://upload.wikimedia.org/wikipedia/commons/9/94/USC_Trojans_logo.svg", conference="Big Ten", mascot="Traveler", colors=["#990000", "#FFC72C"]),
    School(id="7", name="LSU", logo="https://upload.wikimedia.org/wikipedia/commons/2/2e/LSU_Athletics_logo.svg", conference="SEC", mascot="Mike the Tiger", colors=["#461D7C", "#FDD023"]),
    School(id="8", name="Penn State", logo="https://upload.wikimedia.org/wikipedia/commons/5/58/Penn_State_Nittany_Lions_logo.svg", conference="Big Ten", mascot="Nittany Lion", colors=["#041E42", "#FFFFFF"]),
]

@api_router.get("/schools", response_model=List[School])
async def get_schools(conference: Optional[str] = None):
    if conference:
        return [s for s in SCHOOLS if s.conference == conference]
    return SCHOOLS

# ==================== ANALYTICS ROUTES ====================

@api_router.get("/analytics/dashboard", response_model=DashboardMetrics)
async def get_dashboard_metrics(current_user: dict = Depends(get_current_user)):
    # Get campaign counts
    total = await db.campaigns.count_documents({"user_id": current_user["id"]})
    active = await db.campaigns.count_documents({"user_id": current_user["id"], "status": "active"})
    scheduled = await db.campaigns.count_documents({"user_id": current_user["id"], "status": "scheduled"})
    
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
    """Get emotion distribution for the last 7 days"""
    return {
        "euphoria": 35,
        "tension": 25,
        "pride": 18,
        "frustration": 12,
        "anxiety": 6,
        "nostalgia": 3,
        "disappointment": 1
    }

# ==================== MAIN APP SETUP ====================

@api_router.get("/")
async def root():
    return {"message": "Ardito EIP API", "version": "1.0.0"}

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
