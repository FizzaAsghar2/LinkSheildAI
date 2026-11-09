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
def test_report_never_claims_reputation_is_clean(monkeypatch):
 monkeypatch.setattr('app.scanner._safe_host',lambda h:None)
 import app.scanner as scanner
 class Response:
  status_code=200; headers={'content-type':'text/html; charset=utf-8'}; encoding='utf-8'
  def __enter__(self):return self
  def __exit__(self,*a):pass
  def iter_bytes(self):yield b'<html><body><p>Welcome</p></body></html>'
 class Client:
  def __enter__(self):return self
  def __exit__(self,*a):pass
  def stream(self,*a):return Response()
 monkeypatch.setattr(scanner.httpx,'Client',lambda **kw:Client())
 r=scan_url('https://example.com')
 assert r['classification']=='UNKNOWN'
 assert r['reputation']['status']=='unavailable'
def test_password_form_to_unrelated_host_creates_high_finding(monkeypatch):
 monkeypatch.setattr('app.scanner._safe_host',lambda h:None)
 import app.scanner as scanner
 class Response:
  status_code=200; headers={'content-type':'text/html'}; encoding='utf-8'
  def __enter__(self):return self
  def __exit__(self,*a):pass
  def iter_bytes(self):yield b'<form action="https://other.example/collect"><input type="password"></form>'
 class Client:
  def __enter__(self):return self
  def __exit__(self,*a):pass
  def stream(self,*a):return Response()
 monkeypatch.setattr(scanner.httpx,'Client',lambda **kw:Client())
 r=scan_url('https://example.com')
 assert r['classification']=='HIGH'
 assert any(f['id']=='credential_risk' for f in r['findings'])
