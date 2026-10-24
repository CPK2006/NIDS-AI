"""Read-only evidence collector. It never trains or writes into existing paths."""
from pathlib import Path
import hashlib, json, re, sys, traceback

import pandas as pd
import joblib

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent
def write_json(name, value):
    (OUT/name).write_text(json.dumps(value, indent=2, default=str)+"\n", encoding="utf-8")

def sha256(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""): h.update(chunk)
    return h.hexdigest()

# Verify LightGBM artifact checksum and attempt the actual load.
p=ROOT/"results/models/lightgbm_top20_model.pkl"
manifest=(ROOT/"model_artifacts.sha256").read_text(encoding="utf-8")
match=re.search(r"^([0-9a-fA-F]{64})\s+results/models/lightgbm_top20_model\.pkl\s*$",manifest,re.M)
actual=sha256(p) if p.exists() else None
hash_info={"path":"results/models/lightgbm_top20_model.pkl","exists":p.exists(),"sha256":actual,"manifest_sha256":match.group(1) if match else None,"manifest_line_found":bool(match),"match":bool(match and actual and actual.lower()==match.group(1).lower())}
write_json("v1_lightgbm_checksum.json",hash_info)

try:
    model=joblib.load(p)
    params=model.get_params()
    feature_names=getattr(model,"feature_name_",getattr(model,"feature_names_in_",None))
    model_info={"load_status":"loaded","type":f"{type(model).__module__}.{type(model).__name__}","params":params,"n_features_in_":getattr(model,"n_features_in_",None),"feature_names":list(feature_names) if feature_names is not None else None,"booster_num_trees":model.booster_.num_trees() if hasattr(model,"booster_") else None,"classes_":getattr(model,"classes_",None)}
    model_info["classes_"]=model_info["classes_"].tolist() if hasattr(model_info["classes_"],"tolist") else model_info["classes_"]
    write_json("v1_lightgbm_params.json",model_info)
except Exception as e:
    model=None
    write_json("v1_lightgbm_params.json",{"load_status":"failed","artifact":str(p.relative_to(ROOT)),"error_type":type(e).__name__,"error":str(e),"get_params":"Unavailable because joblib could not deserialize without its runtime dependency.","params":None,"n_features_in_":None,"feature_names":None,"booster_num_trees":None,"classes_":None})

# Read dataset and record counts; evaluate only if the saved model loaded.
data_path=ROOT/"data/processed/Friday-WorkingHours-Morning.pcap_ISCX.csv"
eval_data={"dataset":"data/processed/Friday-WorkingHours-Morning.pcap_ISCX.csv","model_evaluation_status":"not run"}
try:
    df=pd.read_csv(data_path)
    y=df["Label"].map(lambda x: 0 if str(x).strip()=="BENIGN" else 1)
    split=int(len(df)*.8)
    train_y=y.iloc[:split]; test_y=y.iloc[split:]
    eval_data.update({"dataset_rows":int(len(df)),"train_rows":int(split),"test_rows":int(len(df)-split),"attack_rows_total":int(y.sum()),"benign_rows_total":int((y==0).sum()),"train_attack_rows":int(train_y.sum()),"train_attack_share":float(train_y.mean()) if len(train_y) else None,"test_attack_rows":int(test_y.sum()),"test_attack_share":float(test_y.mean()) if len(test_y) else None,"test_benign_rows":int((test_y==0).sum()),"test_has_few_or_no_attacks":bool(test_y.sum()<=10)})
    if model is None:
        eval_data["model_evaluation_status"]="not run: saved model could not be loaded"
        eval_data["model_evaluation_error"]="See v1_lightgbm_params.json; current Python lacks the lightgbm package required by joblib pickle."
    else:
        from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score,roc_auc_score,confusion_matrix
        features=["Destination Port","Bwd Packet Length Std","Init_Win_bytes_forward","Init_Win_bytes_backward","Fwd Header Length","Average Packet Size","min_seg_size_forward","Flow IAT Mean","Bwd Header Length","PSH Flag Count","Flow IAT Min","Fwd Packet Length Max","Fwd IAT Min","Total Length of Bwd Packets","Max Packet Length","Fwd IAT Total","Packet Length Std","Flow Bytes/s","Bwd Packet Length Mean","Packet Length Variance"]
        X=df[features].fillna(0).replace([float("inf"),float("-inf")],0)
        Xtr,Xte=X.iloc[:split],X.iloc[split:]
        ytr,yte=y.iloc[:split],y.iloc[split:]
        prob=model.predict_proba(Xte)[:,1]
        eval_data["model_evaluation_status"]="completed"
        eval_data["metrics"]={}
        for threshold in [0.5,0.004]:
            pred=(prob>=threshold).astype(int)
            tn,fp,fn,tp=confusion_matrix(yte,pred,labels=[0,1]).ravel()
            eval_data["metrics"][str(threshold)]={"accuracy":float(accuracy_score(yte,pred)),"precision":float(precision_score(yte,pred,zero_division=0)),"recall":float(recall_score(yte,pred,zero_division=0)),"f1":float(f1_score(yte,pred,zero_division=0)),"roc_auc":float(roc_auc_score(yte,prob)),"TN":int(tn),"FP":int(fp),"FN":int(fn),"TP":int(tp),"FPR":float(fp/(fp+tn)) if fp+tn else None,"FNR":float(fn/(fn+tp)) if fn+tp else None}
except Exception as e:
    eval_data.update({"model_evaluation_status":"failed while reading/evaluating dataset","error_type":type(e).__name__,"error":str(e)})
write_json("v1_lightgbm_eval.json",eval_data)

# CatBoost artifact: record runtime failure separately from saved experiment JSON.
cat_path=ROOT/"results/models/leakage_free_top20_model.cbm"
cat={"artifact":"results/models/leakage_free_top20_model.cbm","exists":cat_path.exists(),"sha256":sha256(cat_path) if cat_path.exists() else None}
try:
    from catboost import CatBoostClassifier
    cb=CatBoostClassifier(); cb.load_model(str(cat_path)); params=cb.get_all_params()
    cat.update({"load_status":"loaded","tree_count_":cb.tree_count_,"best_iteration_":cb.get_best_iteration(),"get_all_params":params,"requested_params":{k:params.get(k) for k in ["iterations","depth","learning_rate","l2_leaf_reg","random_seed","use_best_model","auto_class_weights"]},"feature_names":cb.feature_names_})
except Exception as e:
    cat.update({"load_status":"failed","error_type":type(e).__name__,"error":str(e),"tree_count_":"Unavailable: model could not be loaded","get_all_params":"Unavailable: model could not be loaded","requested_params":{k:"Unavailable: model could not be loaded" for k in ["iterations","depth","learning_rate","l2_leaf_reg","random_seed","use_best_model","auto_class_weights"]},"feature_names":"Unavailable: model could not be loaded"})
    meta=ROOT/"results/models/leakage_free_top20_results.json"
    if meta.exists(): cat["separate_saved_result_metadata"]=json.loads(meta.read_text(encoding="utf-8")).get("catboost")
write_json("catboost_v1_artifact.json",cat)

# Actual split counts from stored y_test and sequential 20% tail.
counts={}
yt=ROOT/"data/splits/y_test.csv"
try:
    ytest=pd.read_csv(yt).iloc[:,0]
    counts["data/splits/y_test.csv"]={"rows":int(len(ytest)),"attack_rows":int((ytest==1).sum()),"benign_rows":int((ytest==0).sum()),"attack_share":float((ytest==1).mean())}
except Exception as e: counts["data/splits/y_test.csv"]={"error":f"{type(e).__name__}: {e}"}
seq=ROOT/"data/sample/cicids2017_binary_deduplicated.csv"
try:
    labels=pd.read_csv(seq,usecols=["Binary_Label"])["Binary_Label"]
    start=int(len(labels)*.8); tail=labels.iloc[start:]
    counts["sequential_final_20_percent"]={"dataset":"data/sample/cicids2017_binary_deduplicated.csv","rows":int(len(tail)),"attack_rows":int((tail==1).sum()),"benign_rows":int((tail==0).sum()),"attack_share":float((tail==1).mean()),"split_definition":"iloc[int(n*0.8):]"}
except Exception as e: counts["sequential_final_20_percent"]={"error":f"{type(e).__name__}: {e}"}
write_json("test_split_counts.json",counts)

# Compare feature order from app source with each saved selection/ranking artifact.
import ast, csv
app_tree=ast.parse((ROOT/"app/app.py").read_text(encoding="utf-8"))
app_features=None
for node in app_tree.body:
    if isinstance(node,(ast.Assign,ast.AnnAssign)):
        targets=node.targets if isinstance(node,ast.Assign) else [node.target]
        if any(isinstance(t,ast.Name) and t.id=="FEATURES" for t in targets):
            app_features=ast.literal_eval(node.value); break
with (ROOT/"results/models/catboost_top20_feature_importance.csv").open(encoding="utf-8-sig",newline="") as f:
    catboost_rank=[r["Feature"] for r in csv.DictReader(f)]
selected=json.loads((ROOT/"data/features/top20/top20_feature_names.json").read_text(encoding="utf-8"))
ranked=json.loads((ROOT/"results/models/top_20_features.json").read_text(encoding="utf-8"))
ranked_names=[x["feature"] for x in ranked]
write_json("feature_order_comparison.json",{"app_FEATURES":app_features,"app_matches_catboost_top20_importance_order":app_features==catboost_rank,"catboost_top20_importance_order":catboost_rank,"data_features_top20_json_order":selected,"app_matches_data_features_top20_json":app_features==selected,"results_models_top_20_features_order":ranked_names,"app_matches_results_top_20_features":app_features==ranked_names})

print(json.dumps({"checksum":hash_info,"v1_load_status":model_info.get("load_status") if model is not None else "failed","eval":eval_data,"catboost_load_status":cat["load_status"],"split_counts":counts},indent=2))
