from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from .settings import settings
kwargs={"check_same_thread":False} if settings.database_url.startswith("sqlite") else {}
engine=create_engine(settings.database_url,connect_args=kwargs)
SessionLocal=sessionmaker(bind=engine,expire_on_commit=False)
Base=declarative_base()
