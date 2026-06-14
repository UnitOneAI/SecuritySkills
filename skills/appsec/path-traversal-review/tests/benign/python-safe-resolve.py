from pathlib import Path


def safe_resolve_under_base(base_dir, user_path):
    base = Path(base_dir).resolve()
    target = (base / user_path).resolve()
    target.relative_to(base)
    return target


def read_report(request, base_dir):
    target = safe_resolve_under_base(base_dir, request.args["file"])
    return target.read_text(encoding="utf-8")
