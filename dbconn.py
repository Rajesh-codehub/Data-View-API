from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os

load_dotenv()


DATABASE_URL = os.getenv("DATABASE_URL")

# create async engine
engine = create_async_engine(DATABASE_URL, echo = True)

# create session factory
async_session = sessionmaker(
    bind = engine,
    class_ = AsyncSession,
    expire_on_commit = False
)

# Dependency to get async session in fastapi endpoint
async def get_db():
    async with async_session() as session:
        yield session



