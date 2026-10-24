"""Copy the minimum app runtime into report_evidence and exercise it there."""
from pathlib import Path
import ast, csv, json, os, shutil, subprocess, sys

EVIDENCE=Path(__file__).resolve().parent
ROOT=EVIDENCE.parent
SANDBOX=EVIDENCE/"sandbox_app"
for rel in ["app","v2","pcap","config","src"]:
    src=ROOT/rel; dst=SANDBOX/rel
    if dst.exists(): shutil.rmtree(dst)
    shutil.copytree(src,dst,ignore=shutil.ignore_patterns("__pycache__","*.pyc",".env"))
for rel in ["results/models/lightgbm_top20_model.pkl","results/models/leakage_free_top20_model.cbm","v2/model/nids_v2_model.pkl"]:
    src=ROOT/rel; dst=SANDBOX/rel; dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(src,dst)
(SANDBOX/"data").mkdir(parents=True,exist_ok=True)

# Reconstruct one input row directly from the already captured stand-alone test output.
lines=(EVIDENCE/"web_prediction_output.txt").read_text(encoding="utf-16",errors="replace").splitlines()
orders=[]
for i,line in enumerate(lines):
    if line.strip()=="Web form order:" and i+1<len(lines):
        try: orders.append([float(v) for v in lines[i+1].strip().split(",")])
        except ValueError: pass
if len(orders)<2:
    raise RuntimeError("Could not recover the two sample rows from saved web prediction output.")

child=r'''import json, os, re
os.environ["NETRA_RUNTIME_ROLE"]="local_sensor"
os.environ["NETRA_EVENT_BACKEND"]="sqlite"
os.environ["NETRA_EVENT_DB_PATH"]=os.path.join(os.getcwd(),"data","isolated_events.sqlite3")
os.environ["NETRA_EMAIL_ALERT_DB_PATH"]=os.path.join(os.getcwd(),"data","isolated_delivery.sqlite3")
os.environ["NETRA_EMAIL_ALERTS_ENABLED"]="false"
os.environ["NETRA_FORWARDING_ENABLED"]="false"
os.environ["PYTHONDONTWRITEBYTECODE"]="1"
from app.app import app, MODEL_LOADED, model, THRESHOLD, RUNTIME_ROLE, FEATURES
from flask import url_for
rows=json.loads(os.environ["NETRA_TEST_ROWS"])
client=app.test_client()
response=client.get("/")
out={"runtime_role":RUNTIME_ROLE,"model_loaded":MODEL_LOADED,"model_type":type(model).__module__+"."+type(model).__name__ if model is not None else None,"threshold":THRESHOLD,"features":FEATURES,"get_status":response.status_code,"get_has_static_metrics_panel":b"Model Evaluation Performance" in response.data,"post_results":[]}
for values in rows:
    response=client.post("/",data=dict(zip(FEATURES,[str(x) for x in values])))
    body=response.get_data(as_text=True)
    label="ATTACK" if "ATTACK DETECTED" in body else "BENIGN" if "BENIGN TRAFFIC" in body else None
    probability=re.search(r"Attack Probability</span>\s*<strong>([0-9.]+)%</strong>",body)
    threshold=re.search(r"Applied Threshold</span>\s*<strong>([0-9.]+)</strong>",body)
    out["post_results"].append({"status":response.status_code,"classification":label,"attack_probability_percent":float(probability.group(1)) if probability else None,"threshold":float(threshold.group(1)) if threshold else None})
print(json.dumps(out,indent=2))
'''
env=os.environ.copy()
env["NETRA_TEST_ROWS"]=json.dumps(orders[:2])
env["PYTHONDONTWRITEBYTECODE"]="1"
env["NETRA_RUNTIME_ROLE"]="local_sensor"
env["NETRA_EVENT_BACKEND"]="sqlite"
env["NETRA_EVENT_DB_PATH"]=str(SANDBOX/"data"/"isolated_events.sqlite3")
env["NETRA_EMAIL_ALERT_DB_PATH"]=str(SANDBOX/"data"/"isolated_delivery.sqlite3")
env["NETRA_EMAIL_ALERTS_ENABLED"]="false"
env["NETRA_FORWARDING_ENABLED"]="false"
env["MODEL_PATH"]=str(SANDBOX/"results/models/lightgbm_top20_model.pkl")
proc=subprocess.run([sys.executable,"-B","-c",child],cwd=SANDBOX,env=env,capture_output=True,text=True,timeout=180)
(EVIDENCE/"isolated_app_test_output.txt").write_text(proc.stdout+proc.stderr,encoding="utf-8")
(EVIDENCE/"isolated_app_test_exit_code.txt").write_text(str(proc.returncode)+"\n",encoding="utf-8")
print(proc.stdout)
if proc.stderr: print(proc.stderr,file=sys.stderr)
print(f"exit_code={proc.returncode}")
