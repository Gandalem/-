"""Discover request and response schemas for the NCP Guard endpoints."""
import json, os, time, urllib.request, urllib.error
from pathlib import Path

BASE = "https://223.130.136.240"
ENDPOINTS = {"prompt":"/guard/prompt/classify", "qwen":"/guard/qwen/classify", "granite":"/guard/granite/classify"}
TEXT = "Please explain phishing. 한국어로 설명해줘. 请简单说明。"
FIELDS = ("text", "prompt", "input", "message")
SECRET = os.environ.get("NCP_API_V2","")

def request(path, field, style, text):
    key_header = {"Authorization":"Bearer "+SECRET} if style=="bearer" else {"X-API-Key":SECRET}
    req=urllib.request.Request(BASE+path, data=json.dumps({field:text},ensure_ascii=False).encode("utf-8"), headers={"Content-Type":"application/json", **key_header}, method="POST")
    begin=time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=30) as f:
            raw=f.read(25000)
            code=f.status
        try:
            obj=json.loads(raw)
            shape={k: (str(v)[:90] if k.lower() in {"label","category","prediction","result","verdict","decision","risk","score","confidence","is_attack","is_injection","unsafe","status","error","classification"} else type(v).__name__) for k,v in obj.items()} if isinstance(obj,dict) else {"top_type":type(obj).__name__}
        except Exception:
            shape={"body":"non-json"}
        return {"status":code,"seconds":round(time.monotonic()-begin,3),"shape":shape}
    except urllib.error.HTTPError as e:
        # Avoid logging bodies or headers; status alone discloses no credentials.
        return {"status":e.code,"seconds":round(time.monotonic()-begin,3)}
    except Exception as e:
        return {"status":"EXCEPTION","exception_type":type(e).__name__,"seconds":round(time.monotonic()-begin,3)}

def main():
    if not SECRET:
        print("Missing NCP_API_V2 secret")
        return 2
    records={}
    for name,path in ENDPOINTS.items():
        trials=[]
        success=None
        for style in ("bearer","x_api_key"):
            for field in FIELDS:
                r=request(path,field,style,TEXT)
                trials.append({"auth":style,"field":field,**r})
                print(name,style,field,"status",r["status"],"seconds",r["seconds"],flush=True)
                if r["status"]==200:
                    success={"auth":style,"field":field,**r}
                    print("SHAPE",name,json.dumps(r.get("shape",{}),ensure_ascii=False),flush=True)
                    break
                if r["status"] in (401,403):
                    break
                if r["status"] not in (400,415,422):
                    break
            if success:
                break
        records[name]={"success":success,"trials":trials}
        time.sleep(2)
    Path("results").mkdir(exist_ok=True)
    Path("results/guard_probe.json").write_text(json.dumps(records,indent=2,ensure_ascii=False),encoding="utf-8")
    print("WORKING ENDPOINTS",sum(bool(r["success"]) for r in records.values()),"/3",flush=True)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
