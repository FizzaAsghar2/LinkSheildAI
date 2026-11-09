import pytest
from app.scanner import validate_url,_safe_host,scan_url
def test_rejects_unsupported_schemes():
 with pytest.raises(ValueError):validate_url('file:///etc/passwd')
def test_rejects_localhost():
 with pytest.raises(ValueError):validate_url('http://localhost/admin')
def test_blocks_private_ip():
 with pytest.raises(ValueError):_safe_host('192.168.1.1')
def test_unknown_when_fetch_fails(monkeypatch):
 monkeypatch.setattr('app.scanner._safe_host',lambda h:None)
 import app.scanner as scanner
 class Client:
  def __enter__(self):return self
  def __exit__(self,*a):pass
  def get(self,*a):raise OSError()
 monkeypatch.setattr(scanner.httpx,'Client',lambda **kw:Client())
 r=scan_url('https://example.com')
 assert r['classification']=='UNKNOWN'
