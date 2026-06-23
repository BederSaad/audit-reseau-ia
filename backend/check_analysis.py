import asyncio
from main import AsyncSessionLocal, AuditAnalysis, Scan
from sqlalchemy.future import select
from services.audit_analysis import fetch_audit_analysis

async def check():
    async with AsyncSessionLocal() as session:
        # Get all scans sorted by date
        scan_res = await session.execute(select(Scan).order_by(Scan.started_at.desc()).limit(5))
        scans = scan_res.scalars().all()
        
        print(f'Total scans: {len(scans)}')
        
        for scan in scans:
            print(f'\n--- Scan ID: {scan.id} ---')
            print(f'Status: {scan.status}')
            print(f'Started: {scan.started_at}')
            
            # Check if analysis exists
            analysis_res = await session.execute(select(AuditAnalysis).where(AuditAnalysis.scan_id == scan.id))
            analysis = analysis_res.scalar_one_or_none()
            
            if analysis:
                print(f'[OK] Analysis exists in database')
                print(f'  Security Score: {analysis.security_score}')
                print(f'  AI Generated: {analysis.ai_generated}')
            else:
                print(f'[FAIL] NO analysis in database')
            
            # Test fetch function
            fetched = await fetch_audit_analysis(scan.id)
            if fetched:
                print(f'[OK] fetch_audit_analysis works')
            else:
                print(f'[FAIL] fetch_audit_analysis returns None')

asyncio.run(check())
