import asyncio
from sqlalchemy import text
from database import engine

async def add_columns():
    async with engine.begin() as conn:
        await conn.execute(text("""
            ALTER TABLE hosts 
            ADD COLUMN IF NOT EXISTS is_mobile BOOLEAN DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS scan_type VARCHAR(20),
            ADD COLUMN IF NOT EXISTS screenshot_path VARCHAR,
            ADD COLUMN IF NOT EXISTS evidence JSONB DEFAULT '[]'::jsonb;
        """))
        print("[OK] Columns added successfully")

if __name__ == "__main__":
    asyncio.run(add_columns())