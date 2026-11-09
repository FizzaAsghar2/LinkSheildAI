import base64,ipaddress,re,socket
from urllib.parse import urlsplit,urljoin
import httpx
from bs4 import BeautifulSoup
from .settings import settings

SCANNER_VERSION="2.0.0"

def validate_url(value:str)->str:
    if len(value)>2048: raise ValueError("URL is too long")
    p=urlsplit(value.strip())
    if p.scheme.lower() not in ("http","https") or not p.hostname or p.username or p.password: raise ValueError("Enter a valid HTTP or HTTPS URL without embedded credentials")
    _safe_host(p.hostname)
    return p.geturl()

def _safe_host(host):
    try: h=host.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError: raise ValueError("Invalid internationalized hostname")
    if h.lower() in ("localhost","metadata.google.internal") or h.lower().endswith(".localhost"): raise ValueError("Local and metadata hosts are blocked")
    try: addresses=[ipaddress.ip_address(h)]
    except ValueError:
        try: addresses=[ipaddress.ip_address(x[4][0]) for x in socket.getaddrinfo(h,None,type=socket.SOCK_STREAM)]
        except socket.gaierror: raise ValueError("Domain did not resolve")
    if not addresses or any(not a.is_global for a in addresses): raise ValueError("Private, local, and non-public network addresses are blocked")

def _expand_static_text(source:str)->str:
    """Decode a few bounded, common JavaScript obfuscation wrappers without executing code."""
    expanded=[source[:500000]]; current=expanded[0]
    current=re.sub(r"\\x([0-9a-fA-F]{2})",lambda m:chr(int(m.group(1),16)),current)
    current=re.sub(r"\\u([0-9a-fA-F]{4})",lambda m:chr(int(m.group(1),16)),current)
    expanded.append(current[:500000])
    def chars(m):
        try:return "".join(chr(int(x)%256) for x in re.findall(r"\d{1,3}",m.group(1)))
        except Exception:return ""
    current=re.sub(r"(?:String\.)?fromCharCode\s*\(([\d,\s]{3,2048})\)",chars,current,flags=re.I)
    expanded.append(current[:500000])
    for m in list(re.finditer(r"(?:atob|Buffer\.from)\s*\(\s*['\"]([A-Za-z0-9+/=_-]{16,8192})['\"]",current,re.I))[:100]:
        raw=m.group(1).replace("-","+").replace("_","/")
        try: expanded.append(base64.b64decode(raw+"="*((-len(raw))%4),validate=False).decode("utf-8",errors="ignore")[:64000])
        except Exception: pass
    return "\n".join(expanded)[:700000]

def _network_targets(source:str,page_url:str):
    patterns=(r"\b(?:fetch|sendBeacon|EventSource|WebSocket)\s*\(\s*['\"]([^'\"]{1,2048})['\"]",r"\b\w+\.open\s*\(\s*['\"](?:GET|POST|PUT|PATCH|DELETE)['\"]\s*,\s*['\"]([^'\"]{1,2048})['\"]",r"\baxios\.(?:get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]{1,2048})['\"]")
    page_host=(urlsplit(page_url).hostname or "").lower(); targets=set(); static_found=False
    for pattern in patterns:
        for match in re.finditer(pattern,source,re.I):
            static_found=True
            try: target=(urlsplit(urljoin(page_url,match.group(1))).hostname or "").lower().rstrip(".")
            except Exception: continue
            if target: targets.add(target)
    third_party=sorted(x for x in targets if x!=page_host and not x.endswith("."+page_host))
    return {"targets":sorted(targets)[:20],"third_party":third_party[:20],"destination_unresolved":bool(re.search(r"\b(sendBeacon|XMLHttpRequest|fetch|WebSocket|EventSource)\b",source,re.I) and not static_found)}

def _script_signals(source:str,page_url:str):
    expanded=_expand_static_text(source); compact=re.sub(r"[^a-z0-9]","",expanded.lower())
    has=lambda *tokens:any(token in compact for token in tokens)
    password_value=bool(re.search(r"(?:querySelector|querySelectorAll|getElementsByName)\s*\([^)]{0,200}(?:password|type\s*=\s*['\"]password)[^;]{0,500}(?:\.value\b|\[['\"]value['\"]\])",expanded,re.I))
    credential_storage=bool(re.search(r"(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\(\s*['\"][^'\"]{0,80}(?:token|auth|password|credential|session)[^'\"]{0,80}['\"]",expanded,re.I))
    destinations=_network_targets(expanded,page_url)
    return {
        "expanded":expanded,
        "media":has("getusermedia","getdisplaymedia","webkitgetusermedia"),
        "recorder":has("mediarecorder"),
        "stream_capture":has("capturestream"),
        "transmit":bool(re.search(r"\b(sendBeacon|WebSocket|XMLHttpRequest|fetch|EventSource)\b",expanded,re.I)),
        "rtc_transport":has("rtcpeerconnection"),
        "background":has("setinterval","visibilitychange","documenthidden","pagehide","beforeunload","requestanimationframe"),
        "dynamic_eval":bool(re.search(r"\beval\s*\(|\bnew\s+Function\s*\(",expanded,re.I)),
        "encoded":bool(re.search(r"\batob\s*\(|fromCharCode|base64",expanded,re.I)),
        "sensitive_read":password_value,
        "credential_storage":credential_storage,
        "cookie_read":bool(re.search(r"\bdocument\s*\.\s*cookie\b",expanded,re.I)),
        "network_targets":destinations["targets"],
        "third_party_targets":destinations["third_party"],
        "destination_unresolved":destinations["destination_unresolved"],
    }

def _site_identity(host:str):
    host=host.lower().rstrip(".")
    for entry in settings.official_domains.split(";"):
        if "=" not in entry: continue
        domain,name=(part.strip() for part in entry.split("=",1)); domain=domain.lower().rstrip(".")
        if domain and (host==domain or host.endswith("."+domain)):
            return {"status":"verified_official_allowlist","name":name or domain,"domain":domain,"detail":"This domain matches the locally configured official-domain allowlist. Site behavior is assessed separately."}
    if host.endswith(".edu.pk"):
        return {"status":"educational_namespace","name":None,"domain":host,"detail":"The .edu.pk namespace is designated for Pakistani educational institutes; this identifies the registration category, not whether this page's code is safe."}
    if host.endswith(".gov.pk") or host.endswith((".gob.pk",".gog.pk",".gkp.pk",".gop.pk",".gos.pk",".gok.pk")):
        return {"status":"government_namespace","name":None,"domain":host,"detail":"This uses a Pakistani government namespace; domain category does not certify the page's current behavior."}
    if host.endswith(".ac.pk"):
        return {"status":"academic_namespace_unverified","name":None,"domain":host,"detail":"This uses an academic namespace; registration alone does not verify accreditation or current page behavior."}
    return {"status":"unverified","name":None,"domain":host,"detail":"No configured official-domain match or recognized Pakistani institutional namespace was found."}

def _lookup_reputation(url:str):
    """Optional URL reputation lookup. Disabled by default because it sends URLs to Google."""
    if not settings.web_risk_enabled or not settings.web_risk_api_key:
        return {"status":"unavailable","provider":"Google Web Risk","detail":"Lookup is disabled or not configured; no URL was sent to a reputation provider."}
    params=[("threatTypes","MALWARE"),("threatTypes","SOCIAL_ENGINEERING"),("threatTypes","UNWANTED_SOFTWARE"),("uri",url),("key",settings.web_risk_api_key)]
    try:
        with httpx.Client(timeout=min(settings.request_timeout_seconds,5),follow_redirects=False) as client:
            response=client.get("https://webrisk.googleapis.com/v1/uris:search",params=params)
        if response.status_code!=200:
            return {"status":"unavailable","provider":"Google Web Risk","detail":"Reputation provider returned an error; no clean verdict was assumed."}
        types=response.json().get("threat",{}).get("threatTypes",[])
        if types:
            return {"status":"malicious","provider":"Google Web Risk","threat_types":types,"detail":"Google Web Risk matched this URL on threat lists: "+", ".join(types)+"."}
        return {"status":"no_match","provider":"Google Web Risk","detail":"No match was returned by Google Web Risk; absence from these lists does not establish safety."}
    except Exception:
        return {"status":"unavailable","provider":"Google Web Risk","detail":"Reputation lookup failed; no clean verdict was assumed."}

def scan_url(url):
    url=validate_url(url); findings=[]; evidence=[]; final=url; html=""; fetched=False; error=None
    try:
        with httpx.Client(timeout=settings.request_timeout_seconds,follow_redirects=False,headers={"User-Agent":"LinkShieldAI/1.0 (+security research scanner)"}) as client:
            current=url
            for _ in range(4):
                p=urlsplit(current); _safe_host(p.hostname)
                with client.stream("GET",current) as response:
                    if response.status_code in (301,302,303,307,308):
                        loc=response.headers.get("location")
                        if not loc: break
                        current=validate_url(urljoin(current,loc)); continue
                    final=current
                    if "text/html" in response.headers.get("content-type","").lower():
                        parts=[]; total=0
                        for chunk in response.iter_bytes():
                            take=chunk[:max(0,settings.max_response_bytes-total)]
                            parts.append(take); total+=len(take)
                            if total>=settings.max_response_bytes: break
                        html=b"".join(parts).decode(response.encoding or "utf-8",errors="replace"); fetched=True
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
        # Fetch a bounded set of public script resources for static inspection.
        # Never execute downloaded code; validate every destination to prevent SSRF.
        inline_tags=[s for s in soup.find_all("script") if not s.get("src") and (not s.get("type") or "javascript" in s.get("type","").lower() or "module" in s.get("type","").lower())]
        script_sources=[(f"inline script {i+1}",s.get_text(" ",strip=True)) for i,s in enumerate(inline_tags) if s.get_text(strip=True)]
        script_bytes=sum(len(x.encode("utf-8",errors="ignore")) for _,x in script_sources)
        inspected=0; skipped=0; script_limit=12; byte_limit=700000; per_script_limit=100000
        for i,src in enumerate(scripts[:script_limit]):
            if script_bytes>=byte_limit: break
            try:
                script_url=validate_url(urljoin(final,src))
                _safe_host(urlsplit(script_url).hostname or "")
                with httpx.Client(timeout=settings.request_timeout_seconds,follow_redirects=False,headers={"User-Agent":"LinkShieldAI/1.0 (+security research scanner)"}) as script_client:
                    with script_client.stream("GET",script_url) as script_response:
                        if script_response.status_code!=200: skipped+=1; continue
                        content_type=script_response.headers.get("content-type","").lower()
                        if content_type and not any(x in content_type for x in ("javascript","ecmascript","text/plain","octet-stream")):
                            skipped+=1; continue
                        parts=[]; size=0
                        for chunk in script_response.iter_bytes():
                            take=chunk[:max(0,min(per_script_limit,byte_limit-script_bytes-size))]
                            parts.append(take); size+=len(take)
                            if size>=per_script_limit or script_bytes+size>=byte_limit: break
                        if parts:
                            script_sources.append((f"external script {i+1}: {urlsplit(script_url).hostname or 'unknown host'}",b"".join(parts).decode(script_response.encoding or "utf-8",errors="replace"))); script_bytes+=size; inspected+=1
            except Exception: skipped+=1
        external_count=len(scripts)
        if inspected: evidence.append(f"Statically inspected {inspected} of {external_count} external script reference(s); scripts were not executed.")
        if skipped or external_count>script_limit or script_bytes>=byte_limit: evidence.append("Script inspection was partial; some resources were skipped, exceeded scan limits, or were not retrieved.")
        if not scripts and not inline_tags: evidence.append("No statically addressable JavaScript was found in the retrieved HTML; runtime-loaded scripts may still exist.")
        js="\n".join(text for _,text in script_sources)[:byte_limit]
        ast_ok=False; ast_parser_available=False; ast_error=""
        try:
            import esprima
            ast_parser_available=True
            esprima.parseScript(js,tolerant=True)
            ast_ok=True
        except ImportError: ast_error="JavaScript AST parser is not installed."
        except Exception: ast_error="JavaScript AST parsing was incomplete for this syntax."
        signals=[_script_signals(text,final) for _,text in script_sources]
        merged={key:any(x[key] for x in signals) for key in ("media","recorder","stream_capture","transmit","rtc_transport","background","dynamic_eval","encoded","sensitive_read","credential_storage","cookie_read")}
        runtime_loader=bool(re.search(r"\bimport\s*\(|\bimportScripts\s*\(|createElement\s*\(\s*['\"]script",js,re.I))
        behavior_hints=[]
        for (name,_),sig in zip(script_sources,signals):
            labels=[]
            for key,label in (("media","media capture API"),("recorder","MediaRecorder"),("stream_capture","stream capture"),("transmit","network API"),("rtc_transport","WebRTC transport"),("background","page-lifetime trigger"),("dynamic_eval","dynamic code evaluation"),("encoded","encoded text"),("sensitive_read","password-field value read"),("credential_storage","named credential/token storage read"),("cookie_read","cookie access")):
                if sig[key]: labels.append(label)
            if labels: behavior_hints.append(name+": "+", ".join(labels))
        matched=[name for (name,_),sig in zip(script_sources,signals) if sig["media"] or sig["recorder"] or sig["transmit"] or sig["background"]]
        media_recorder=[name for (name,_),sig in zip(script_sources,signals) if sig["media"] and (sig["recorder"] or sig["stream_capture"])]
        media_exfil=[name for (name,_),sig in zip(script_sources,signals) if sig["media"] and (sig["recorder"] or sig["stream_capture"]) and sig["transmit"]]
        media_rtc=[name for (name,_),sig in zip(script_sources,signals) if sig["media"] and sig["rtc_transport"]]
        media_persistent=[name for (name,_),sig in zip(script_sources,signals) if sig["media"] and sig["background"] and (sig["transmit"] or sig["recorder"] or sig["stream_capture"] or sig["rtc_transport"])]
        credential_exfil=[name for (name,_),sig in zip(script_sources,signals) if sig["sensitive_read"] and sig["transmit"]]
        credential_external=[sig["third_party_targets"] for sig in signals if sig["sensitive_read"] and sig["transmit"] and sig["third_party_targets"]]
        media_external=[sig["third_party_targets"] for sig in signals if sig["media"] and (sig["recorder"] or sig["stream_capture"]) and sig["transmit"] and sig["third_party_targets"]]
        third_party_destinations=sorted({target for sig in signals for target in sig["third_party_targets"]})
        unresolved_destinations=any(sig["destination_unresolved"] for sig in signals)
        obfuscated_sensitive=[name for (name,_),sig in zip(script_sources,signals) if sig["dynamic_eval"] and sig["encoded"] and (sig["media"] or sig["sensitive_read"])]
        if merged["media"]: findings.append(_finding("media_permission","low","JavaScript references camera, microphone, or screen capture APIs","Inspected JavaScript contains getUserMedia/getDisplayMedia family API names.","This is a capability indicator. The page may be able to request media permission, but static inspection cannot prove permission was granted."))
        if media_recorder:
            findings.append(_finding("media_recording","medium","Media capture and recording APIs appear together","The same script source contains media capture plus MediaRecorder or stream-capture APIs: "+", ".join(media_recorder[:4]),"If executed after permission is granted, this code could record audio, video, or a screen stream."))
        if media_exfil:
            destinations=sorted({d for group in media_external for d in group})
            findings.append(_finding("media_capture_exfiltration","high" if destinations else "medium","Media capture, recording, and outbound transmission patterns co-occur","The same script source contains media capture, a recording/stream API, and a network API: "+", ".join(media_exfil[:4])+("; third-party destinations: "+", ".join(destinations) if destinations else "; no literal third-party destination was resolved"),"If this code executes after permission is granted, it may send captured media. A third-party destination raises the risk; static inspection cannot establish execution or intent."))
        if media_rtc:
            findings.append(_finding("media_realtime_transport","medium","Media capture is combined with a real-time peer connection","The same script source contains media capture APIs and RTCPeerConnection: "+", ".join(media_rtc[:4]),"This combination can transmit captured audio or video after permission is granted, and is also common in legitimate calling apps. Review the destination and page purpose."))
        if media_persistent:
            findings.append(_finding("persistent_media_behavior","medium","Media APIs are combined with page-lifetime triggers and communication","The same script source combines media APIs, page-lifetime triggers, and recording or network communication: "+", ".join(media_persistent[:4]),"This pattern could keep media capture or transmission active while the page is open or in the background; static inspection cannot prove it runs."))
        if credential_exfil:
            destinations=sorted({d for group in credential_external for d in group})
            findings.append(_finding("sensitive_data_transmission","high" if destinations else "medium","A script reads a password field and also makes network requests","The same script source selects a password input, reads its value, and uses a network API: "+", ".join(credential_exfil[:4])+("; third-party destinations: "+", ".join(destinations) if destinations else "; destination is first-party or unresolved"),"Password submission is common on login pages. Sending a read password value to a third-party host is a strong exfiltration signal; static inspection cannot prove the code executed."))
        if obfuscated_sensitive:
            findings.append(_finding("obfuscated_script","medium","Encoded dynamic code touches media or password-input capabilities","The same script source combines encoded/dynamic code patterns with media capture or password-field value access: "+", ".join(obfuscated_sensitive[:4]),"This combination may hide behavior from static inspection. No decoded or target code was executed."))
        if runtime_loader: evidence.append("The page appears to load JavaScript at runtime; those dynamically selected resources may not be included in this report.")
        if behavior_hints: evidence.append("Script indicator locations: "+"; ".join(behavior_hints[:8]))
        if js and not ast_ok: evidence.append(ast_error+" Bounded deobfuscation and pattern checks ran, but hidden or runtime-generated behavior may remain undetected.")
        script_analysis={"inline_scripts":len(inline_tags),"external_references":external_count,"external_inspected":inspected,"external_skipped":skipped,"bytes_inspected":script_bytes,"ast_parser_available":ast_parser_available,"ast_parsed":ast_ok,"runtime_script_loading_detected":runtime_loader,"dynamic_execution":False,"behavior_source_hints":behavior_hints[:8],"third_party_destinations":third_party_destinations,"network_destination_unresolved":unresolved_destinations}
        evidence.append(f"Retrieved HTML successfully ({len(html)} characters); JavaScript inspection covered {len(script_sources)} script source(s) and never executed code.")
    elif error: evidence.append(error)
    reputation=_lookup_reputation(url)
    if reputation.get("status")=="malicious":
        findings.append(_finding("reputation_match","critical","URL matched a known threat-intelligence list",reputation.get("detail","A configured reputation provider matched this URL."),"This URL is listed by a threat-intelligence provider as associated with malicious or unwanted activity."))
    evidence.append(reputation.get("detail","Reputation status unavailable."))
    # Keep related heuristics in one family and combine separate families with a small bonus.
    weights={"credential_risk":75,"reputation_match":95,"suspicious_url":10,"script_behavior":25,"media_capture_exfiltration":75,"media_realtime_transport":75,"persistent_media_behavior":45,"sensitive_data_transmission":35,"media_recording":32,"obfuscated_script":18,"redirect":15,"iframe":3,"media_permission":8}
    groups={"credential_risk":"credentials","sensitive_data_transmission":"credentials","reputation_match":"reputation","media_permission":"media","media_recording":"media","media_capture_exfiltration":"media","media_realtime_transport":"media","persistent_media_behavior":"media","suspicious_url":"navigation","redirect":"navigation","script_behavior":"script","obfuscated_script":"script","iframe":"embedded"}
    group_scores={}
    for item in {x["id"]:x for x in findings}.values():
        group=groups.get(item["id"],item["id"])
        points=75 if item["id"]=="sensitive_data_transmission" and item.get("severity")=="high" else weights.get(item["id"],10)
        group_scores[group]=max(group_scores.get(group,0),points)
    score_parts=sorted(group_scores.items(),key=lambda x:x[1],reverse=True)
    score=min(100,score_parts[0][1]+sum(value for _,value in score_parts[1:])//4) if score_parts else 0
    score_breakdown=[{"category":name,"points":value} for name,value in score_parts]
    # A successful fetch and absence of detected indicators do not establish safety.
    if score == 0 and not findings:
        classification="UNKNOWN"
    else:
        classification="CRITICAL" if score>=80 else "HIGH" if score>=60 else "MEDIUM" if score>=40 else "LOW"
    if error and not findings: classification="UNKNOWN"
    severe=any(f.get("severity") in ("high","critical") for f in findings)
    incomplete=(not fetched or not ast_ok or bool(script_analysis.get("external_skipped")) or script_analysis.get("external_references",0)>script_limit or script_analysis.get("bytes_inspected",0)>=byte_limit or script_analysis.get("runtime_script_loading_detected")) if fetched else True
    confidence="low" if incomplete else "medium"
    identity=_site_identity(urlsplit(final).hostname or host)
    official_identity=identity["status"] in ("verified_official_allowlist","educational_namespace","government_namespace")
    verdict="SUSPICIOUS" if severe else "SAFE" if official_identity and not incomplete and score<40 else "INCONCLUSIVE" if incomplete or not findings else "REVIEW"
    return {"url":url,"final_url":final,"domain":urlsplit(final).hostname or host,"identity":identity,"scanner_version":SCANNER_VERSION,"scanned_at":__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),"risk_score":score,"classification":classification,"verdict":verdict,"score_meaning":"Evidence-weighted score grouped by related indicators; not a probability or safety guarantee. Official identity and observed page behavior are assessed separately.","score_breakdown":score_breakdown,"confidence":confidence,"findings":findings,"evidence":evidence,"script_analysis":locals().get("script_analysis",{}),"reputation":reputation,"dynamic_analysis":"Disabled: no isolated disposable browser is configured. Actual permission grants, recording, and runtime network traffic were not observed.","explanation":""}

def _finding(kind,severity,title,technical,impact):
    return {"id":kind,"severity":severity,"title":title,"technical_evidence":technical,"possible_impact":impact,"recommendation":"Avoid entering sensitive information until you verify the destination and its operator."}
