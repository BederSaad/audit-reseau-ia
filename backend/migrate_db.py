import asyncio
from sqlalchemy import text
from database import engine, Base
from models import *

async def migrate_db():
    """Drop the problematic risk_score_history table and recreate schema."""
    async with engine.begin() as conn:
        print("Dropping all tables with CASCADE...")
        # Use raw SQL to drop all tables with CASCADE to handle dependencies
        tables_to_drop = [
            "risk_score_history",
            "llm_decision_logs",
            "audit_analysis",
            "vulnerabilities",
            "services",
            "hosts",
            "scans"
        ]
        for table in tables_to_drop:
            try:
                await conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
                print(f"  [OK] Dropped {table}")
            except Exception as e:
                print(f"  Note for {table}: {e}")
        
        print("Creating all tables with new schema...")
        await conn.run_sync(Base.metadata.create_all)
        print("[OK] Created all tables")
    
    print("\n[SUCCESS] Database migration complete!")
    print("The audit_analysis table now has:")
    print("  - attack_narrative (replaced technical_overview)")
    print("  - strategic_recommendations (replaced recommendations)")

if __name__ == "__main__":
    asyncio.run(migrate_db())
