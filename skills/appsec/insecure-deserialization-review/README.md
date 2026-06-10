# Insecure Deserialization Review

This skill reviews untrusted deserialization paths in Java and Python, with
special attention to native object streams, pickle-family loaders, unsafe YAML
constructors, polymorphic JSON binding, side-effectful object hooks, integrity
controls, and migration paths.

## Three-step usage

1. Point the agent at code that parses request bodies, cookies, queues, caches,
   uploaded files, or stored serialized blobs.
2. Run the `insecure-deserialization-review` skill and produce the inventory
   table plus findings.
3. Verify fixes with the included vulnerable and benign fixtures before marking
   the issue resolved.

## Included evidence

- Three vulnerable fixtures under `tests/vulnerable/`.
- Three benign fixtures under `tests/benign/`.
- A pattern reference under `references/patterns.md`.
