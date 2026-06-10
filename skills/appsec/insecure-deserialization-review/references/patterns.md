# Insecure Deserialization Pattern Reference

## High-confidence vulnerable patterns

| Pattern | Why it matters |
|---|---|
| `ObjectInputStream.readObject()` on request, queue, cache, or upload data | Java serialization can instantiate unexpected classes and trigger gadget methods. |
| `pickle.load`, `pickle.loads`, `dill.load`, `cloudpickle.load`, or `marshal.loads` on untrusted data | Python native serialization can execute code or construct arbitrary objects. |
| `yaml.load` with unsafe loaders | YAML tags can materialize Python objects or call constructors. |
| Polymorphic JSON with payload-controlled class names | Attackers can select unexpected concrete types. |
| Signed native blobs without type restrictions | Integrity does not make native object graphs safe. |
| Legacy deserialization selected by attacker-controlled version fields | Migration compatibility can keep unsafe loaders reachable. |

## Required safe evidence

- Data-only parser or a strict object filter is used.
- Allowed concrete types are enumerated and endpoint scoped.
- Untrusted class/type names are rejected before object creation.
- Side-effect hooks are absent or unreachable for deserialized DTOs.
- Size, depth, array, and reference limits are enforced.
- Legacy formats are time-bound, monitored, and deny-by-default.
