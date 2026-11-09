from sqlalchemy import Column,Integer,String,DateTime,JSON,ForeignKey,Text
from sqlalchemy.orm import relationship
from .db import Base
class Scan(Base):
    __tablename__="scans"
    id=Column(Integer,primary_key=True,index=True)
    url=Column(String(2048),nullable=False,index=True)
    status=Column(String(20),nullable=False,default="pending")
    risk_score=Column(Integer,nullable=True)
    classification=Column(String(20),nullable=True)
    created_at=Column(DateTime(timezone=True),nullable=False)
    scanned_at=Column(DateTime(timezone=True),nullable=True)
    result=Column(JSON,nullable=False,default=dict)
    findings=relationship("ScanFinding",cascade="all, delete-orphan")
    evidence=relationship("ScanEvidence",cascade="all, delete-orphan")
    explanations=relationship("AIExplanation",cascade="all, delete-orphan")
    metadata_rows=relationship("ScanMetadata",cascade="all, delete-orphan")

class ScanFinding(Base):
    __tablename__="scan_findings"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id",ondelete="CASCADE"),index=True,nullable=False)
    finding_key=Column(String(80)); severity=Column(String(20)); title=Column(String(300)); details=Column(JSON,nullable=False)

class ScanEvidence(Base):
    __tablename__="scan_evidence"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id",ondelete="CASCADE"),index=True,nullable=False)
    detail=Column(Text,nullable=False)

class AIExplanation(Base):
    __tablename__="ai_explanations"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id",ondelete="CASCADE"),index=True,nullable=False)
    created_at=Column(DateTime(timezone=True),nullable=False); explanation=Column(Text,nullable=False); provider=Column(String(40),nullable=False)

class ScanMetadata(Base):
    __tablename__="scan_metadata"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id",ondelete="CASCADE"),index=True,nullable=False)
    key=Column(String(80),nullable=False); value=Column(JSON,nullable=False)
