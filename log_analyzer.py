import re
from collections import Counter
IP=re.compile(r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")
TS=re.compile(r"^\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}:\\d{2}")
def analyze_lines(lines):
 out=[]
 for line in lines:
  if not line.strip():continue
  s=line.lower()
  if any(x in s for x in ("sql injection","command injection","malware","ransomware","critical")):sev,reason="CRITICAL","Potential malicious activity"
  elif any(x in s for x in ("multiple failed","brute force","brute-force","unauthorized","denied","blocked","error")):sev,reason="HIGH","Error or access-control event"
  elif any(x in s for x in ("failed login","warning","invalid password")):sev,reason="MEDIUM","Authentication warning"
  else:sev,reason="LOW","Routine activity"
  ip=IP.search(line);ts=TS.search(line);out.append({"timestamp":ts.group(0) if ts else "Unknown","source_ip":ip.group(0) if ip else "Unknown","severity":sev,"reason":reason,"message":line.strip()})
 c=Counter(x["severity"] for x in out)
 return {"total_events":len(out),"unique_sources":len({x["source_ip"] for x in out if x["source_ip"]!="Unknown"}),"severity_counts":{s:c.get(s,0) for s in ("CRITICAL","HIGH","MEDIUM","LOW")},"events":out}
