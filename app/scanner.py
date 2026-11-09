import ipaddress,re,socket
from urllib.parse import urlsplit,urljoin
import httpx
from bs4 import BeautifulSoup
from .settings import settings

def validate_url(value:str)->str:
    if len(value)>2048: raise ValueError("URL is too long")
    p=urlsplit(value.strip())
    if p.scheme.lower() not in ("http","https") or not p.hostname or p.username or p.password: raise ValueError("Enter a valid HTTP or HTTPS URL without embedded credentials")
    _safe_host(p.hostname)
    return p.geturl()

def _safe_host(host):
    h=host.rstrip(".").encode("idna").decode("ascii")
    if h.lower() in ("localhost","metadata.google.internal") or h.lower().endswith(".localhost"): raise ValueError("Local and metadata hosts are blocked")
    try: addresses=[ipaddress.ip_address(h)]
    except ValueError:
        try: addresses=[ipaddress.ip_address(x[4][0]) for x in socket.getaddrinfo(h,None,type=socket.SOCK_STREAM)]
        except socket.gaierror: raise ValueError("Domain did not resolve")
    if not addresses or any(not a.is_global for a in addresses): raise ValueError("Private, local, and non-public network addresses are blocked")

def scan_url(url):
    url=validate_url(url); findings=[]; evidence=[]; final=url; html=""; fetched=False; error=None
    try:
        with httpx.Client(timeout=settings.request_timeout_seconds,follow_redirects=False,headers={"User-Agent":"LinkShieldAI/1.0 (+security research scanner)"}) as client:
            current=url
            for _ in range(4):
                p=urlsplit(current); _safe_host(p.hostname)
                response=client.get(current)
                if response.status_code in (301,302,303,307,308):
                    loc=response.headers.get("location")
                    if not loc: break
                    current=validate_url(urljoin(current,loc)); continue
                final=current
                if "text/html" in response.headers.get("content-type","").lower():
                    body=response.content[:settings.max_response_bytes]
                    html=body.decode(response.encoding or "utf-8",errors="replace"); fetched=True
                break
            else: error="Redirect limit reached"
    except Exception as exc:
        error="Site could not be safely retrieved: "+(str(exc)[:180] if isinstance(exc,ValueError) else type(exc).__name__)
    p=urlsplit(url); host=p.hostname or ""; labels=host.split(".")
    suspicious=[]
    if len(host)>70:suspicious.append("Unusually long hostname")
    if host.count("-")>=4:suspicious.append("Hostname contains many hyphens")
    if re.search(r"(login|verify|secure|account).*(login|verify|secure|account)",host,re.I): suspicious.append("Hostname combines multiple account or security terms")
    if p.scheme=="http": suspicious.append("Connection uses HTTP without transport encryption")
    for item in suspicious: findings.append(_finding("suspicious_url", "medium",item,"The URL structure can be used to make a destination look more trustworthy, but is not proof of malicious intent.",item))
    if fetched:
        soup=BeautifulSoup(html,"html.parser"); pw=soup.select('input[type="password"]'); forms=soup.find_all("form")
        if pw:
            evidence.append(f"Found {len(pw)} password input(s) in retrieved HTML.")
            for form in forms:
                action=form.get("action") or final; target=urlsplit(urljoin(final,action)).hostname or ""
                if target.lower()!=host.lower():
                    findings.append(_finding("credential_risk","high","Password form submits to a different hostname",f"Password input action resolves to {target} while the scanned hostname is {host}.","Credentials may be disclosed to an unrelated destination if this form is submitted."))
        scripts=[s.get("src") for s in soup.find_all("script") if s.get("src")]
        external=[s for s in scripts if (urlsplit(urljoin(final,s)).hostname or "").lower()!=host.lower()]
        if external: evidence.append(f"Found {len(external)} script reference(s) hosted on a different hostname.")
        if soup.find("iframe",src=True):
            frames=[x.get("src") for x in soup.find_all("iframe",src=True)]
            findings.append(_finding("iframe","low","Embedded frame(s) detected",f"HTML contains {len(frames)} iframe(s); their content was not executed or inspected.","An embedded frame can display third-party content."))
        refresh=soup.find("meta",attrs={"http-equiv":re.compile("refresh",re.I)})
        if refresh: findings.append(_finding("redirect","medium","Meta refresh redirect detected",str(refresh.get("content", ""))[:200],"The page may navigate the browser to another location."))
        # Analyze only inline code statically; external scripts are not fetched/executed.
        js="\n".join(s.get_text(" ",strip=True) for s in soup.find_all("script") if not s.get("src"))[:300000]
        combos=[]
        if re.search(r"\beval\s*\(|new\s+Function\s*\(",js): combos.append("dynamic code evaluation")
        if re.search(r"atob\s*\(|base64",js,re.I): combos.append("base64 decoding")
        if re.search(r"document\.cookie|querySelector[^;]{0,120}password|\.value",js,re.I): combos.append("sensitive browser data access pattern")
        if re.search(r"fetch\s*\(|XMLHttpRequest|sendBeacon",js): combos.append("outbound request API")
        if len(combos)>=2: findings.append(_finding("script_behavior","medium","Multiple suspicious JavaScript patterns co-occur",", ".join(combos),"This combination can be used to collect or transmit data, but static inspection cannot establish execution or malicious intent."))
        if re.search(r"getUserMedia|mediaDevices",js): findings.append(_finding("media_permission","low","Script references camera or microphone permission APIs","Inline JavaScript references getUserMedia/mediaDevices.","A permission request does not prove camera or microphone access occurred."))
        evidence.append(f"Retrieved HTML successfully ({len(html)} characters); page JavaScript was not executed.")
    elif error: evidence.append(error)
    # Cap correlated observations of the same class to avoid score inflation.
    weights={"credential_risk":65,"suspicious_url":18,"script_behavior":32,"redirect":24,"iframe":8,"media_permission":8}
    score=min(100,sum(weights.get(f["id"],10) for f in {x["id"]:x for x in findings}.values()))
    score=min(score,100)
    classification=("CRITICAL" if score>=80 else "HIGH" if score>=60 else "MEDIUM" if score>=40 else "LOW" if score>=20 else "SAFE") if fetched or findings else "UNKNOWN"
    if error and not findings: classification="UNKNOWN"
    confidence="low" if not fetched else "medium" if findings else "low"
    return {"url":url,"final_url":final,"domain":host,"scanned_at":__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),"risk_score":score,"classification":classification,"confidence":confidence,"findings":findings,"evidence":evidence,"reputation":{"status":"unavailable","detail":"No threat-intelligence provider is configured; unavailable is not a clean result."},"dynamic_analysis":"skipped; isolated disposable browser not configured","explanation":""}

def _finding(kind,severity,title,technical,impact):
    return {"id":kind,"severity":severity,"title":title,"technical_evidence":technical,"possible_impact":impact,"recommendation":"Avoid entering sensitive information until you verify the destination and its operator."}
