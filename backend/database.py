from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base

# Remplace la ligne SQLite par celle-ci pour PostgreSQL
# Format : postgresql+asyncpg://user:password@host:port/database_name
SQLALCHEMY_DATABASE_URL = "postgresql+asyncpg://postgres:postgres@localhost:5432/audit_db"

engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL,
    echo=False
)

SessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

Base = declarative_base()

async def get_db():
    async with SessionLocal() as session:
        yield session