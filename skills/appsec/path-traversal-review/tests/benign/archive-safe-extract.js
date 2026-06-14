import fs from "node:fs";
import path from "node:path";

function safeResolveArchiveMember(extractRoot, memberPath) {
  const root = path.resolve(extractRoot);
  const target = path.resolve(root, memberPath);
  const relative = path.relative(root, target);
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("Archive member escapes extraction root");
  }
  return target;
}

export function writeArchiveMember(entry, extractRoot) {
  const target = safeResolveArchiveMember(extractRoot, entry.path);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, entry.contents);
}
