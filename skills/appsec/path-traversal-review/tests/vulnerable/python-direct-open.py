import os


def read_report(request, base_dir):
    name = request.args["file"]
    target = os.path.join(base_dir, name)
    with open(target, "r", encoding="utf-8") as handle:
        return handle.read()
