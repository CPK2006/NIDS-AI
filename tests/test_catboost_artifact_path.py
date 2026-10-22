"""Source-level contract test for the V1 CatBoost fallback artifact path."""

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _assigned_string(source_path: Path, variable_name: str) -> str:
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == variable_name
            for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if not isinstance(value, str):
                raise AssertionError(f"{variable_name} must be a string path")
            return value.replace("\\", "/")
    raise AssertionError(f"{variable_name} assignment was not found")


def _runtime_catboost_fallback_path(source_path: Path) -> str:
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "load_model" or not node.args:
            continue
        path_call = node.args[0]
        if not isinstance(path_call, ast.Call) or not isinstance(path_call.func, ast.Attribute):
            continue
        if path_call.func.attr != "join" or len(path_call.args) < 2:
            continue
        if not (
            isinstance(path_call.args[0], ast.Name)
            and path_call.args[0].id == "PROJECT_ROOT"
        ):
            continue
        components = [ast.literal_eval(arg) for arg in path_call.args[1:]]
        if components[:2] == ["results", "models"]:
            return Path(*components).as_posix()
    raise AssertionError("V1 CatBoost fallback path was not found")


def test_catboost_training_output_matches_v1_runtime_fallback():
    training_path = _assigned_string(
        ROOT / "scripts" / "train_leakage_free_top20.py", "MODEL_OUTPUT"
    )
    runtime_path = _runtime_catboost_fallback_path(ROOT / "app" / "app.py")

    assert training_path == runtime_path
