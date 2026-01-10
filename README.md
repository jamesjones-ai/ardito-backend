# Ardito EIP Backend

FastAPI backend for the Ardito Emotion Intelligence Platform with StackForDevs authentication integration.

## Features

- Validates StackForDevs JWT tokens for authentication
- Games API (live games, emotion data)
- Campaigns management
- Analytics and dashboard metrics
- School information

## Deployment to Render

1. Push this repository to GitHub
2. Go to Render Dashboard
3. Create new Web Service from GitHub repo
4. Render will auto-detect the Dockerfile
5. Deploy!

## API Endpoints

### Games
- `GET /api/games/live` - Get live games
- `GET /api/games/{game_id}` - Get specific game
- `GET /api/games/{game_id}/emotions` - Get emotion data for game

### Campaigns (requires authentication)
- `GET /api/campaigns` - List user campaigns
- `POST /api/campaigns` - Create campaign
- `GET /api/campaigns/{id}` - Get campaign details
- `PUT /api/campaigns/{id}/status` - Update campaign status
- `DELETE /api/campaigns/{id}` - Delete campaign

### Schools
- `GET /api/schools` - List schools
- `GET /api/schools?conference=SEC` - Filter by conference

### Analytics (requires authentication)
- `GET /api/analytics/dashboard` - Get dashboard metrics
- `GET /api/analytics/activations` - Get recent activations
- `GET /api/analytics/emotions` - Get emotion distribution

## Authentication

Frontend sends StackForDevs JWT token in Authorization header:
```
Authorization: Bearer <token>
```

Backend validates the token using StackForDevs JWKS endpoint.
