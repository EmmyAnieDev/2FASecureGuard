from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import engine

import models
import uvicorn

from routes import auth_router

# Create the database tables
models.Base.metadata.create_all(bind=engine)

load_dotenv()

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

APP_PORT = 8000

@app.get('/')
async def api_root():
    return {f"message: Api is running!..."}

@app.get('/server')
async def sever_health():
    return {f"message: Server is healthy!..."}

app.include_router(auth_router, prefix=f'/api/v1/auth', tags=['auth'])


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)