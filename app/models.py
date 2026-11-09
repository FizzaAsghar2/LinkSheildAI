from sqlalchemy import Column,Integer,String,DateTime,JSON
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
