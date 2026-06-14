import fs from "node:fs";
import path from "node:path";

export function readAttachment(req, baseDir) {
  const file = req.query.file;
  const target = path.join(baseDir, file);
  return fs.readFileSync(target, "utf8");
}
