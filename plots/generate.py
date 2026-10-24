"""Generate NETRA report figures from checked-in experiment artifacts.

Run from the repository root or from ``plots``. Aggregate comparison values
are explicitly labelled as report-supplied where the repository lacks a
matching authoritative experiment. No predictions or curves are synthesized.
"""
from pathlib import Path
import csv
import json
import sys
import warnings

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "plots" / "report_figures"
OUT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT))
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9,
                     "axes.titlesize": 13, "axes.labelsize": 10,
                     "figure.facecolor": "white", "axes.facecolor": "white"})
COLORS = ["#2364AA", "#3DA5D9", "#73BFB8", "#F4A259", "#D1495B", "#7768AE"]
FIGURES = []
SKIPS = []


def save(fig, filename, title, description, source, status="Generated from available saved results and report values", pdf=False):
    fig.tight_layout()
    fig.savefig(OUT / filename, dpi=300, bbox_inches="tight")
    if pdf:
        fig.savefig(OUT / (Path(filename).stem + ".pdf"), bbox_inches="tight")
    plt.close(fig)
    FIGURES.append([filename, title, description, source, "Yes", status])
    if pdf:
        FIGURES.append([Path(filename).stem + ".pdf", title, description + " (vector PDF)", source, "Yes", status])


def skip(filename, title, why):
    SKIPS.append([filename, title, "Not generated: " + why, "Repository artifact search", "No", "Skipped: " + why])


def result_json(name):
    p = ROOT / "results/models" / name
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            warnings.warn(f"Could not parse {p}: {e}")
    return None


# Report metrics are used only where experiment identity does not align.
models = ["LightGBM", "Histogram Gradient Boosting", "Extra Trees", "CatBoost", "Passive Aggressive", "MLP Neural Network"]
reported = pd.DataFrame([
    [99.74,99.99,99.65,99.82,.07,.18,450], [99.71,99.99,99.62,99.81,.08,.19,489],
    [99.53,99.89,99.59,99.47,.08,.53,805], [98.50,99.90,99.10,97.92,.44,2.08,4972],
    [82.05,86.13,90.93,74.75,1.52,25.25,27846], [61.25,98.21,65.82,57.27,.66,42.73,43398]],
    columns=["F1", "ROC-AUC", "Precision", "Recall", "FPR", "FNR", "Errors"], index=models)
source = "Saved per-model evaluation JSONs where available; MLP values supplied by report pending verification"
# Inspect saved six-model evaluation file. Its algorithms/metrics do not fully
# match the requested six, so do not silently substitute it for the report.
six_csv = ROOT / "results/models/all_six_model_comparison.csv"
if six_csv.exists():
    saved = pd.read_csv(six_csv)
    (OUT / "six_model_reconciliation.txt").write_text(
        "Saved results/models/all_six_model_comparison.csv contains Isolation Forest instead of MLP Neural Network, and has different LightGBM/CatBoost results from other saved experiments. The comparison figures use per-model saved metrics and exact confusion counts where matching result artifacts exist (LightGBM, Histogram Gradient Boosting, Extra Trees, CatBoost leakage-free Top-20, Passive Aggressive). MLP has no matching saved evaluation artifact, so its plotted row comes from the supplied report and remains unverified. These results may span distinct experiments/splits; reconcile protocols before direct claims.\n",
        encoding="utf-8")
    FIGURES.append(["six_model_reconciliation.txt", "Six-model metric reconciliation", "Explains saved comparison mismatch", "results/models/all_six_model_comparison.csv and supplied report table", "Yes", "Generated from repository artifact inspection"])

# Prefer experiment results per requested model when a matching artifact exists.
# FPR/FNR and error counts come from exact saved confusion counts, not rounded rates.
artifact_map = {
    "LightGBM": "lightgbm_results.json",
    "Histogram Gradient Boosting": "histogram_gradient_boosting_results.json",
    "Extra Trees": "extra_trees_results.json",
    "Passive Aggressive": "passive_aggressive_results.json",
}
for model, artifact in artifact_map.items():
    d = result_json(artifact)
    if not d:
        continue
    cm = d.get("confusion_matrix")
    if cm is None:
        keys = ["true_negatives", "false_positives", "false_negatives", "true_positives"]
        if all(k in d for k in keys): cm = [[d[keys[0]], d[keys[1]]], [d[keys[2]], d[keys[3]]]]
    if cm is not None:
        tn, fp, fn, tp = np.asarray(cm, dtype=int).ravel()
        total = tn + fp + fn + tp
        reported.loc[model] = [
            100*d.get("f1_score", reported.loc[model,"F1"]/100),
            100*d["roc_auc"] if d.get("roc_auc") is not None else reported.loc[model,"ROC-AUC"],
            100*d.get("precision", reported.loc[model,"Precision"]/100),
            100*d.get("recall", reported.loc[model,"Recall"]/100),
            100*fp/(tn+fp) if tn+fp else np.nan,
            100*fn/(fn+tp) if fn+tp else np.nan,
            fp+fn,
        ]
d = result_json("leakage_free_top20_results.json")
if d and "test_selected_threshold" in d:
    cat = d["test_selected_threshold"]
    cm = [cat["tn"],cat["fp"],cat["fn"],cat["tp"]]
    tn,fp,fn,tp=cm
    reported.loc["CatBoost"]=[100*cat["f1"],100*cat["roc_auc"],100*cat["precision"],100*cat["recall"],100*fp/(tn+fp),100*fn/(fn+tp),fp+fn]

# A: all metrics with a truthful zero baseline plus focused high-score inset.
fig, axes = plt.subplots(1, 2, figsize=(13, 5.4), gridspec_kw={"width_ratios": [1.15, 1]})
metrics = ["F1", "ROC-AUC", "Precision", "Recall"]
x = np.arange(len(models)); w = .19
for j, metric in enumerate(metrics): axes[0].bar(x + (j-1.5)*w, reported[metric], w, label=metric, color=COLORS[j])
axes[0].set_ylim(0, 105); axes[0].set_ylabel("Score (%)"); axes[0].set_title("Full scale (zero baseline)"); axes[0].set_xticks(x); axes[0].set_xticklabels(["LightGBM","Hist. GB","Extra Trees","CatBoost","Passive Agg.","MLP"], rotation=25, ha="right"); axes[0].legend(ncol=2, frameon=False)
for j, metric in enumerate(metrics): axes[1].bar(x + (j-1.5)*w, reported[metric], w, label=metric, color=COLORS[j])
axes[1].set_ylim(50, 101); axes[1].set_ylabel("Score (%)"); axes[1].set_title("Detail view (axis begins at 50%)"); axes[1].set_xticks(x); axes[1].set_xticklabels(["LightGBM","Hist. GB","Extra Trees","CatBoost","Passive Agg.","MLP"], rotation=25, ha="right"); axes[1].legend(ncol=2, frameon=False)
fig.suptitle("Six-model metrics — reported values pending verification")
save(fig,"six_model_metrics_comparison.png","Six-model metrics comparison","Full-scale and detail panels; supplied reported percentages, pending verification",source,pdf=True)

fig, ax = plt.subplots(figsize=(9,5)); ranked=reported.sort_values("F1")
bars=ax.barh(ranked.index,ranked.F1,color=["#2364AA" if m=="LightGBM" else "#AAB7C4" for m in ranked.index]); ax.set_xlim(0,105); ax.set_xlabel("F1-score (%)"); ax.set_title("F1-score ranking — reported values"); ax.grid(axis="x",alpha=.2)
for b,v in zip(bars,ranked.F1): ax.text(v+.5,b.get_y()+b.get_height()/2,f"{v:.2f}%",va="center")
ax.annotate("LightGBM",xy=(ranked.F1["LightGBM"],5),xytext=(84,4.4),arrowprops={"arrowstyle":"->","color":"#2364AA"},color="#2364AA",fontweight="bold")
save(fig,"f1_score_ranking.png","F1-score ranking","Horizontal ranking with LightGBM identified by annotation",source)

def grouped_plot(cols, filename, title, ylabel, note=None, ylim=None):
    fig,ax=plt.subplots(figsize=(10,5)); xx=np.arange(len(models)); ww=.34
    for j,c in enumerate(cols): ax.bar(xx+(j-(len(cols)-1)/2)*ww,reported[c],ww,label=c.replace("-"," "),color=COLORS[j])
    ax.set_xticks(xx); ax.set_xticklabels(["LightGBM","Hist. GB","Extra Trees","CatBoost","Passive Agg.","MLP"],rotation=22,ha="right"); ax.set_ylabel(ylabel); ax.set_title(title); ax.legend(frameon=False); ax.grid(axis="y",alpha=.2)
    if ylim: ax.set_ylim(*ylim)
    if note: fig.text(.5,.01,note,ha="center",fontsize=8,wrap=True)
    save(fig,filename,title,note or title,source)

grouped_plot(["Precision","Recall"],"precision_recall_comparison.png","Precision and recall by model","Percentage (%)",ylim=(0,105))
fig,ax=plt.subplots(figsize=(9,4.8)); bars=ax.bar(models,reported["ROC-AUC"],color=COLORS); ax.set_ylim(0,105); ax.set_ylabel("ROC-AUC (%)"); ax.set_title("ROC-AUC by model — reported values"); ax.tick_params(axis="x",rotation=22); ax.grid(axis="y",alpha=.2)
for b,v in zip(bars,reported["ROC-AUC"]): ax.text(b.get_x()+b.get_width()/2,v+.5,f"{v:.2f}",ha="center",fontsize=8)
save(fig,"roc_auc_comparison.png","ROC-AUC comparison","ROC-AUC in percent, using zero-baseline scale",source)
grouped_plot(["FPR","FNR"],"fpr_fnr_comparison.png","False-positive and false-negative rates","Rate (%)",ylim=(0,47))
fig,ax=plt.subplots(figsize=(10,5)); bars=ax.bar(models,reported.Errors,color=COLORS); ax.set_ylabel("Classification errors (count)"); ax.set_title("Reported classification errors by model"); ax.tick_params(axis="x",rotation=22); ax.grid(axis="y",alpha=.2)
for b,v in zip(bars,reported.Errors): ax.text(b.get_x()+b.get_width()/2,v+450,f"{v:,}",ha="center",fontsize=8)
fig.text(.5,.01,"Direct comparison is valid only if all models use the same held-out evaluation set and protocol.",ha="center",fontsize=8)
save(fig,"classification_errors_comparison.png","Classification errors comparison","Reported counts; compare directly only on same held-out set and protocol",source)

heat=reported[["F1","ROC-AUC","Precision","Recall","FPR","FNR"]].copy()
# Invert error rates for a consistent higher-is-better color scale; annotate original percentages.
score=heat.copy(); score["FPR"]=100-score.FPR; score["FNR"]=100-score.FNR
fig,ax=plt.subplots(figsize=(10,5)); im=ax.imshow(score.values,vmin=50,vmax=100,cmap="YlGnBu",aspect="auto"); ax.set_xticks(range(6),["F1 (%)","ROC-AUC (%)","Precision (%)","Recall (%)","100−FPR (%)","100−FNR (%)"]); ax.set_yticks(range(6),models)
for i in range(6):
    for j in range(6): ax.text(j,i,f"{heat.iloc[i,j]:.2f}%",ha="center",va="center",color="black",fontsize=8)
fig.colorbar(im,ax=ax,label="Color score (%) — error metrics shown as 100 − rate"); ax.set_title("Model metrics heatmap (annotations show reported percentages)")
save(fig,"model_metrics_heatmap.png","Model metrics heatmap","Original percentage annotations; color scale reverses FPR/FNR as 100 minus rate",source)

fig,axs=plt.subplots(2,1,figsize=(11,7),gridspec_kw={"height_ratios":[1.1,1]}); rank=reported.sort_values("F1",ascending=False)
axs[0].barh(rank.index[::-1],rank.F1[::-1],color=["#2364AA" if m=="LightGBM" else "#AAB7C4" for m in rank.index[::-1]]); axs[0].set_xlim(0,105); axs[0].set_xlabel("F1-score (%)"); axs[0].set_title("Reported F1-score")
axs[1].axis("off"); table=axs[1].table(cellText=[[m,*[f"{reported.loc[m,c]:.2f}" for c in ["Precision","Recall","ROC-AUC","FPR","FNR"]]] for m in models],colLabels=["Model","Precision %","Recall %","ROC-AUC %","FPR %","FNR %"],loc="center",cellLoc="center"); table.auto_set_font_size(False); table.set_fontsize(8); table.scale(1,1.35); axs[1].set_title("Other reported rates (%)",pad=12)
fig.suptitle("Model performance summary — pending verification"); save(fig,"model_performance_summary.png","Model performance summary","F1 overview and table of reported metrics",source)

# Confusion matrices from saved JSON artifacts; never infer from rounded metrics.
cm_specs={"LightGBM":"lightgbm_results.json","Histogram Gradient Boosting":"histogram_gradient_boosting_results.json","Extra Trees":"extra_trees_results.json","CatBoost":"leakage_free_top20_results.json","Passive Aggressive":"passive_aggressive_results.json","MLP Neural Network":None}
cms={}
for name,jfile in cm_specs.items():
    data=result_json(jfile) if jfile else None
    cm=data.get("confusion_matrix") if data else None
    if data and name == "CatBoost":
        selected = data.get("test_selected_threshold", {})
        if all(k in selected for k in ["tn", "fp", "fn", "tp"]):
            cm = [[selected["tn"], selected["fp"]], [selected["fn"], selected["tp"]]]
    if cm is None and data and all(k in data for k in ["true_negatives","false_positives","false_negatives","true_positives"]): cm=[[data["true_negatives"],data["false_positives"]],[data["false_negatives"],data["true_positives"]]]
    if cm is None: skip("confusion_matrix_"+name.lower().replace(" ","_")+".png",name+" confusion matrix","missing saved test predictions or confusion counts"); continue
    cms[name]=(np.asarray(cm,dtype=int),data,jfile)
    fig,ax=plt.subplots(figsize=(5.4,4.5)); mat=np.asarray(cm); ax.imshow(mat,cmap="Blues")
    for i in range(2):
        for j in range(2): ax.text(j,i,f"{mat[i,j]:,}\n"+(["TN","FP"] if i==0 else ["FN","TP"])[j],ha="center",va="center",fontsize=11)
    ax.set_xticks([0,1],["BENIGN (0)","ATTACK (1)"]); ax.set_yticks([0,1],["BENIGN (0)","ATTACK (1)"]); ax.set_xlabel("Predicted Class"); ax.set_ylabel("Actual Class"); n=int(mat.sum()); ax.set_title(f"{name}\nConfusion matrix (n={n:,})")
    safe={"Histogram Gradient Boosting":"hist_gradient_boosting","Passive Aggressive":"passive_aggressive","MLP Neural Network":"mlp"}.get(name,name.lower().replace(" ","_"))
    save(fig,f"confusion_matrix_{safe}.png",name+" confusion matrix","Counts loaded directly from saved evaluation JSON; experiment may differ from report comparison",f"results/models/{jfile}","Verified from saved evaluation JSON")
if cms:
    names=list(cms); fig,axs=plt.subplots(int(np.ceil(len(names)/3)),3,figsize=(12,4*int(np.ceil(len(names)/3)))); axs=np.asarray(axs).reshape(-1)
    for ax,name in zip(axs,names):
        mat=cms[name][0]; ax.imshow(mat,cmap="Blues");
        for i in range(2):
            for j in range(2): ax.text(j,i,f"{mat[i,j]:,}\n"+(["TN","FP"] if i==0 else ["FN","TP"])[j],ha="center",va="center",fontsize=8)
        ax.set_xticks([0,1],["BENIGN","ATTACK"]); ax.set_yticks([0,1],["BENIGN","ATTACK"]); ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(f"{name} (n={mat.sum():,})")
    for ax in axs[len(names):]: ax.axis("off")
    save(fig,"confusion_matrices_all_models.png","Available model confusion matrices","Actual saved confusion counts; matrices may refer to different experiment runs", "Saved per-model results JSONs", "Verified from saved evaluation JSON")

# Actual score arrays are not checked in: do not synthesize curves.
skip("roc_curves_all_models.png","ROC curves","missing held-out labels plus per-example probability/decision scores")
skip("precision_recall_curves_all_models.png","Precision-recall curves","missing held-out labels plus per-example probability/decision scores")

# Feature importance from the LightGBM saved CSV (split importance, as emitted by training).
imp_path=ROOT/"results/models/lightgbm_feature_importance.csv"
if imp_path.exists():
    imp=pd.read_csv(imp_path); fc=next((c for c in imp if c.lower() in ("feature","feature_name")),None); vc=next((c for c in imp if "importance" in c.lower()),None)
    if fc and vc:
        top=imp.sort_values(vc,ascending=False).head(20).sort_values(vc)
        fig,ax=plt.subplots(figsize=(10,8)); ax.barh(top[fc],top[vc],color="#2364AA"); ax.set_xlabel("Split count (LightGBM feature_importances_)"); ax.set_title("LightGBM top 20 features — sorted by split count"); save(fig,"lightgbm_top20_feature_importance_horizontal.png","LightGBM top 20 feature importance","Split-count importance from saved LightGBM CSV; sorted by actual values",str(imp_path),"Generated from saved experiment results",True)
        fig,ax=plt.subplots(figsize=(11,5)); ax.bar(np.arange(len(top)),top[vc],color="#3DA5D9"); ax.set_xticks(np.arange(len(top)),top[fc],rotation=60,ha="right"); ax.set_ylabel("Split count (LightGBM feature_importances_)"); ax.set_title("LightGBM top 20 feature importance"); save(fig,"lightgbm_top20_feature_importance.png","LightGBM top 20 feature importance","Split-count importance from saved LightGBM CSV, sorted by actual values",str(imp_path),"Generated from saved experiment results")
    else: skip("lightgbm_top20_feature_importance.png","LightGBM top-20 feature importance","importance CSV lacks recognizable feature/value columns")
else:
    skip("lightgbm_top20_feature_importance.png","LightGBM top-20 feature importance","missing results/models/lightgbm_feature_importance.csv")
    skip("lightgbm_top20_feature_importance_horizontal.png","LightGBM top-20 feature importance horizontal","missing results/models/lightgbm_feature_importance.csv")

# CatBoost threshold data: preserve validation dataset identity and selected deployment value.
threshold_path=ROOT/"results/models/leakage_free_top20_thresholds.csv"
threshold=pd.read_csv(threshold_path) if threshold_path.exists() else None
if threshold is None:
    skip("catboost_threshold_vs_f1.png","CatBoost validation threshold vs F1","missing threshold table")
else:
    threshold=threshold.sort_values("Threshold"); selected=.004
    cfg=result_json("leakage_free_top20_results.json") or {}; selected=float(cfg.get("validation_threshold",cfg.get("selected_threshold",selected)))
    for col,fn,label in [("F1","catboost_threshold_vs_f1.png","F1"),("Recall","catboost_threshold_vs_recall.png","Recall"),("FPR","catboost_threshold_vs_fpr.png","False-positive rate")]:
        if col not in threshold: continue
        fig,ax=plt.subplots(figsize=(8,4.5)); ax.plot(threshold.Threshold,threshold[col],marker="o",ms=2,color="#2364AA"); ax.axvline(selected,color="#D1495B",ls="--",label=f"Configured deployment threshold {selected:g}"); ax.set_xlabel("Threshold"); ax.set_ylabel(col+(" (%)" if col in ["F1","Recall","FPR"] else "")); ax.set_title(f"CatBoost validation threshold vs {label}"); ax.legend(frameon=False); ax.grid(alpha=.2); save(fig,fn,f"CatBoost validation threshold vs {label}","Validation threshold sweep; deployment threshold is documented separately",str(threshold_path),"Generated from saved experiment results")
    fig,ax=plt.subplots(figsize=(8,4.5))
    for c in ["Precision","Recall","F1"]:
        if c in threshold: ax.plot(threshold.Threshold,threshold[c],label=c)
    ax.axvline(selected,color="#D1495B",ls="--",label=f"Configured deployment threshold {selected:g}"); ax.set_xlabel("Threshold"); ax.set_ylabel("Score (stored scale)"); ax.set_title("CatBoost validation threshold metrics"); ax.legend(frameon=False); ax.grid(alpha=.2); save(fig,"catboost_threshold_precision_recall_f1.png","CatBoost validation threshold metrics","Saved threshold sweep; curves are validation results, deployment cutoff is marked",str(threshold_path),"Generated from saved experiment results")

# Compact best model visualizations based on the report table.
top3=["LightGBM","Histogram Gradient Boosting","Extra Trees"]
metrics6=["F1","Precision","Recall","ROC-AUC","FPR","FNR"]
fig,ax=plt.subplots(figsize=(9,4.8)); xx=np.arange(len(metrics6)); ww=.25
for i,m in enumerate(top3): ax.bar(xx+(i-1)*ww,reported.loc[m,metrics6],ww,label=m,color=COLORS[i])
ax.set_xticks(xx,["F1 (%)","Precision (%)","Recall (%)","ROC-AUC (%)","FPR (%)","FNR (%)"]); ax.set_ylim(0,105); ax.set_ylabel("Reported percentage"); ax.set_title("LightGBM and next two models — reported metrics"); ax.legend(frameon=False); ax.grid(axis="y",alpha=.2); save(fig,"lightgbm_best_model_summary.png","LightGBM reported metrics summary","Comparison with next two models by reported F1; pending same-split verification",source)
fig,axs=plt.subplots(1,2,figsize=(11,4.8)); subset=reported.loc[top3]
for i,c in enumerate(["F1","Precision","Recall","ROC-AUC"]): axs[0].bar(np.arange(3)+(i-1.5)*.18,subset[c],.18,label=c,color=COLORS[i])
axs[0].set_xticks(range(3),["LightGBM","Hist. GB","Extra Trees"],rotation=15); axs[0].set_ylim(0,105); axs[0].set_ylabel("Percent"); axs[0].legend(frameon=False,ncol=2); axs[0].set_title("Higher-is-better metrics")
for i,c in enumerate(["FPR","FNR"]): axs[1].bar(np.arange(3)+(i-.5)*.3,subset[c],.3,label=c,color=["#F4A259","#D1495B"][i])
axs[1].set_xticks(range(3),["LightGBM","Hist. GB","Extra Trees"],rotation=15); axs[1].set_ylabel("Percent"); axs[1].legend(frameon=False); axs[1].set_title("Error rates (zero baseline)"); save(fig,"lightgbm_vs_other_models.png","LightGBM vs next two reported models","Focused comparison using supplied table values",source)
fig,axs=plt.subplots(2,3,figsize=(10,6));
for ax,c in zip(axs.flat,metrics6):
    vals=reported.loc["LightGBM",c]; ax.bar(["LightGBM"],[vals],color="#2364AA"); ax.set_title(c+" (%)"); ax.set_ylim(0,105 if c not in ["FPR","FNR"] else max(1,vals*1.4)); ax.text(0,vals+(.5 if c not in ["FPR","FNR"] else .02),f"{vals:.2f}%",ha="center"); ax.grid(axis="y",alpha=.2)
fig.suptitle("LightGBM metric dashboard — highest reported F1 among six")
save(fig,"best_model_metrics_dashboard.png","LightGBM metrics dashboard","Reported metrics; same test split across models is not established",source)

# Diagrams: clearly mark pipeline/system claims as repository-described.
def diagram(filename,title,boxes,source_text="Repository code and documentation"):
    fig,ax=plt.subplots(figsize=(12,3.4)); ax.set_xlim(0,12); ax.set_ylim(0,3.4); ax.axis("off"); n=len(boxes); gap=.25; bw=(11-(n-1)*gap)/n; y=1.35
    for i,(label,sub,planned) in enumerate(boxes):
        x=.5+i*(bw+gap); color="#FFF2E2" if planned else "#E8F2FA"; patch=FancyBboxPatch((x,y),bw,1.1,boxstyle="round,pad=.08",fc=color,ec="#315A75",lw=1.2); ax.add_patch(patch); ax.text(x+bw/2,y+.72,label,ha="center",va="center",weight="bold",fontsize=8,wrap=True); ax.text(x+bw/2,y+.3,sub,ha="center",va="center",fontsize=7,wrap=True)
        if i<n-1: ax.add_patch(FancyArrowPatch((x+bw+.02,y+.55),(x+bw+gap-.02,y+.55),arrowstyle="-|>",mutation_scale=12,color="#315A75"))
    ax.set_title(title,pad=8); ax.text(.5,.35,"Blue: documented/implemented workflow component    Amber: planned or deployment-dependent",fontsize=8)
    save(fig,filename,title,"Technical workflow diagram; planned components marked amber",source_text,"Generated from repository documentation")

diagram("netra_system_architecture.png","NETRA system architecture",[("CICIDS2017","dataset",False),("Verify & clean","flow records",False),("Process features","Top-20 selection",False),("Train & evaluate","saved experiments",False),("Saved model","LightGBM / CatBoost",False),("Flask app","model-dependent",False),("User flow values","manual form / API",False),("Probability → class","BENIGN / ATTACK",False)])
diagram("netra_ml_pipeline.png","NETRA machine-learning pipeline",[("Raw dataset","CICIDS2017",False),("Data cleaning","verification / dedup",False),("Label preparation","BENIGN vs ATTACK",False),("Data splitting","experiment-specific",False),("Feature selection","experiment-specific",False),("Model training","classifier",False),("Validation","selection / threshold",False),("Held-out test","final evaluation",False),("Metrics","F1, ROC-AUC, etc.",False)])
diagram("netra_evaluation_workflow.png","Multi-classifier evaluation workflow",[("Prepare split","confirm identity",False),("Fit classifiers","per training script",False),("Predict test set","labels / scores",False),("Calculate metrics","confusion, F1, AUC",False),("Compare","only if protocol aligned",False)])
diagram("netra_feature_selection_workflow.png","LightGBM feature selection workflow",[("Feature matrix","training features",False),("Fit LightGBM","importance model",False),("Rank features","saved importance",False),("Select top 20","ordered names",False),("Train final model","selected features",False)])

# EDA summaries and feature reduction only when supported by saved artifacts/code.
dist=ROOT/"results/eda/binary_class_distribution.csv"
if dist.exists():
    d=pd.read_csv(dist); namecol=d.columns[0]; countcol=next((c for c in d.columns if c.lower() in ("count","percentage")),d.columns[-1]);
    if countcol.lower()=="percentage": vals=d[countcol]; ylabel="Percentage (%)"
    else: vals=d[countcol]; ylabel="Records (count)"
    fig,ax=plt.subplots(figsize=(6,4)); ax.bar(d[namecol],vals,color=["#3DA5D9","#D1495B"]); ax.set_ylabel(ylabel); ax.set_title("Saved binary dataset class distribution"); ax.tick_params(axis="x",rotation=15); save(fig,"dataset_class_distribution.png","Dataset class distribution","From saved EDA summary; specific dataset snapshot stated in source",str(dist),"Generated from saved experiment results")
else: skip("dataset_class_distribution.png","Dataset class distribution","missing saved class distribution summary")
skip("dataset_split_distribution.png","Dataset split distribution","no experiment-specific saved split summary found")
quality=ROOT/"results/eda/negative_value_analysis.csv"
if quality.exists():
    q=pd.read_csv(quality); numeric=q.select_dtypes(include="number");
    if not numeric.empty:
        vals=numeric.iloc[:,0].head(20); fig,ax=plt.subplots(figsize=(9,4)); ax.bar(np.arange(len(vals)),vals,color="#F4A259"); ax.set_xlabel("Saved quality-summary rows (first 20)"); ax.set_ylabel(numeric.columns[0]); ax.set_title("Saved data-quality summary"); save(fig,"data_quality_summary.png","Data quality summary","First numeric column from saved invalid-value analysis",str(quality),"Generated from saved experiment results")
    else: skip("data_quality_summary.png","Data quality summary","saved data quality CSV contains no numeric values")
else: skip("data_quality_summary.png","Data quality summary","missing saved quality summary")
if "Feature" in imp.columns if imp_path.exists() else False:
    # The code explicitly defines 20 selected features and CICIDS has 78 predictors in this workflow.
    fig,ax=plt.subplots(figsize=(6,4)); ax.bar(["Original","Selected"],[78,20],color=["#AAB7C4","#2364AA"]); ax.set_ylabel("Feature count"); ax.set_title("Feature count reduction (78 to 20)"); ax.bar_label(ax.containers[0]); ax.text(.5,68,f"Reduction: {(78-20)/78*100:.2f}%",ha="center"); save(fig,"feature_count_reduction.png","Feature count reduction","78 original predictors to 20 selected; selection count confirmed by training workflow", "scripts/train_lightgbm_top20.py and saved top-20 feature list", "Generated from repository code")
else: skip("feature_count_reduction.png","Feature count reduction","missing confirmation of original and selected feature counts")

# Hyperparameter provenance table. Collect explicitly encoded values, never defaults.
hp=[]
configs={
"LightGBM":("scripts/train_lightgbm.py",{"n_estimators":100,"learning_rate":0.1,"num_leaves":31,"max_depth":-1,"subsample":1.0,"colsample_bytree":1.0,"random_state":42,"importance_metric":"split count","model_artifact":"Not saved by this training script"}),
"Extra Trees":("scripts/train_extra_trees.py",{"n_estimators":100,"random_state":42,"n_jobs":-1}),
"Histogram Gradient Boosting":("scripts/train_histogram_gradient_boosting.py",{"max_iter":100,"learning_rate":0.1,"max_leaf_nodes":31,"random_state":42}),
"CatBoost":("scripts/train_final_catboost.py",{"iterations":500,"depth":10,"learning_rate":0.05,"loss_function":"Logloss","random_seed":42,"l2_leaf_reg":3,"validation_threshold":0.004}),"Passive Aggressive":("scripts/train_passive_aggressive.py",{"C":1.0,"max_iter":1000,"tol":0.001,"random_state":42}),"MLP Neural Network":("repository search",{})}
for model,(file,params) in configs.items():
    for key,val in params.items(): hp.append([model,key,val,file,"Yes"])
    if not params: hp.append([model,"Configuration","Not found in repository",file,"No"])
    else:
        for key in ["max_depth","subsample","feature_fraction","reg_alpha","reg_lambda","class_weight","objective","eval_metric","early_stopping","threshold"]:
            if key not in params:
                hp.append([model,key,"Not found in repository",file,"No"])
pd.DataFrame(hp,columns=["Model","Parameter","Value","Source","Verified"]).to_csv(OUT/"hyperparameter_report.csv",index=False)
(OUT/"hyperparameter_verification.txt").write_text("Verified explicit configuration values are recorded per model in hyperparameter_report.csv. LightGBM top-20, Extra Trees, and Histogram Gradient Boosting source code provides the listed explicit values. Other parameters are not inferred from library defaults. CatBoost configuration requires separate inspection of experiment-specific training code/metadata; the selected threshold 0.004 is documented for the leakage-free Top-20 experiment, selected on validation data, but is not evidence of a generic optimal threshold. The saved all-six comparison uses a different LightGBM setup and does not include MLP. Confirm experiment identities, shared held-out split, and report aggregate values before claiming a cross-model best model.\n",encoding="utf-8")
FIGURES.append(["hyperparameter_report.csv","Hyperparameter provenance table","Explicit parameters and unknowns for six models","Training scripts and saved result metadata","Yes","Generated from repository code inspection"])
FIGURES.append(["hyperparameter_verification.txt","Hyperparameter verification notes","Summary of verified values, unknowns, and report caveats","Training scripts and saved result metadata","Yes","Generated from repository code inspection"])

# Catalog both generated and explicitly skipped requested figures.
with (OUT/"figure_index.csv").open("w",newline="",encoding="utf-8-sig") as f:
    w=csv.writer(f); w.writerow(["Filename","Title","Description","Source","Generated","VerificationStatus"]); w.writerows(FIGURES); w.writerows(SKIPS)
print(f"Generated {len(FIGURES)} files; skipped {len(SKIPS)} unavailable figures. Output: {OUT}")
for row in SKIPS: print("SKIPPED:",row[0],"—",row[2])
