import fs from "node:fs";
import path from "node:path";

function safeResolveUnderBase(baseDir, userPath) {
  const base = path.resolve(baseDir);
  const target = path.resolve(base, userPath);
  const relative = path.relative(base, target);
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("Path escapes base directory");
  }
  return target;
}

export function readAttachment(req, baseDir) {
  return fs.readFileSync(safeResolveUnderBase(baseDir, req.query.file), "utf8");
}
