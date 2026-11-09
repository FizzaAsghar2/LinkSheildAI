from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from .db import Base, engine, SessionLocal
from .models import Scan
from .scanner import scan_url
from .settings import settings

Base.metadata.create_all(bind=engine)
app = FastAPI(title="LinkShield AI", version="1.0.0", description="Evidence-based website security investigations")
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in settings.allowed_origins.split(",") if x.strip() and "*" not in x], allow_origin_regex=r"chrome-extension://.*", allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type"])

class ScanRequest(BaseModel):
    url: str

def perform(scan_id: int):
    db=SessionLocal()
    try:
        row=db.get(Scan,scan_id)
        if not row:return
        row.status="running"; db.commit()
        result=scan_url(row.url)
        row.status="completed"; row.result=result; row.risk_score=result["risk_score"]; row.classification=result["classification"]; row.scanned_at=datetime.now(timezone.utc); db.commit()
    except Exception as e:
        row=db.get(Scan,scan_id)
        if row: row.status="failed"; row.result={"error":"Scan could not be completed safely."}; db.commit()
    finally: db.close()

@app.get("/health")
def health(): return {"status":"ok","service":"linkshield-api"}

@app.post("/api/v1/scans", status_code=202)
def create_scan(body: ScanRequest, tasks: BackgroundTasks):
    # Validate before persisting or scheduling network access.
    from .scanner import validate_url
    try: normalized=validate_url(body.url)
    except ValueError as e: raise HTTPException(422,str(e))
    db=SessionLocal(); row=Scan(url=normalized,status="pending",created_at=datetime.now(timezone.utc),result={}); db.add(row); db.commit(); db.refresh(row); tasks.add_task(perform,row.id); out=serialize(row); db.close(); return out

@app.get("/api/v1/scans")
def list_scans(limit:int=Query(50,ge=1,le=200), q:str|None=None):
    db=SessionLocal(); query=db.query(Scan)
    if q: query=query.filter(Scan.url.contains(q))
    rows=query.order_by(Scan.created_at.desc()).limit(limit).all(); out=[serialize(r) for r in rows]; db.close(); return out

@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id:int):
    db=SessionLocal(); row=db.get(Scan,scan_id)
    if not row: db.close(); raise HTTPException(404,"Scan not found")
    out=serialize(row); db.close(); return out

@app.get("/api/v1/reports/{scan_id}")
def report(scan_id:int):
    result=get_scan(scan_id)
    if result["status"]!="completed": raise HTTPException(409,"Report is not ready")
    return result["result"]

@app.delete("/api/v1/scans/{scan_id}",status_code=204)
def delete_scan(scan_id:int):
    db=SessionLocal(); row=db.get(Scan,scan_id)
    if not row: db.close(); raise HTTPException(404,"Scan not found")
    db.delete(row); db.commit(); db.close()

@app.post("/api/v1/extension/check")
def extension_check(body:ScanRequest):
    from .scanner import validate_url
    try: url=validate_url(body.url)
    except ValueError as e: raise HTTPException(422,str(e))
    # Shared deterministic scan engine; no second reputation/scanning implementation.
    result=scan_url(url)
    return {"url":url,"risk_score":result["risk_score"],"classification":result["classification"],"findings":result["findings"],"status":"completed"}

@app.get("/api/v1/settings")
def get_settings(): return {"ai_explanations_available":bool(settings.cerebras_api_key),"retention":"Local SQLite; delete individual scans from history.","dynamic_analysis":"Disabled: no isolated disposable execution environment configured."}

@app.post("/api/v1/explanations/{scan_id}")
def explain(scan_id:int):
    result=report(scan_id)
    from .ai import explain_report
    return {"explanation":explain_report(result),"available":bool(settings.cerebras_api_key)}

def serialize(r):
    return {"id":r.id,"url":r.url,"status":r.status,"risk_score":r.risk_score,"classification":r.classification,"created_at":r.created_at.isoformat() if r.created_at else None,"scanned_at":r.scanned_at.isoformat() if r.scanned_at else None,"result":r.result}
