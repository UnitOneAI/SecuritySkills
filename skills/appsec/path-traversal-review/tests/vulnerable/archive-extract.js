import fs from "node:fs";
import path from "node:path";

export function writeArchiveMember(entry, extractRoot) {
  const target = path.join(extractRoot, entry.path);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, entry.contents);
}
