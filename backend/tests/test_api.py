from fastapi.testclient import TestClient
from app.main import app

def test_health():
 with TestClient(app) as c:
  r=c.get('/health')
  assert r.status_code==200 and r.json()['status']=='ok'

def test_invalid_scan_url_is_rejected():
 with TestClient(app) as c:
  r=c.post('/api/v1/scans',json={'url':'file:///etc/passwd'})
  assert r.status_code==422
