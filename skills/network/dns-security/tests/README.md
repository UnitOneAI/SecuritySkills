# DNS Security Test Fixtures

These fixtures exercise the resolver-chain guidance added in version 1.0.1.

- `benign/local-proxy-encrypted-egress/` should not be reported as plaintext external forwarding because BIND forwards to a local proxy and the proxy has verified encrypted upstream egress.
- `vulnerable/external-plaintext-forwarder/` should be reported as Medium because the resolver forwards directly to external recursive resolvers over plaintext DNS.
- `vulnerable/unmanaged-browser-doh/` should be reported as High when enterprise DNS filtering is required because browser DoH can bypass the managed resolver path.

