# Benign: downstream rejects wrong audience

```go
claims, err := verifier.Verify(ctx, token)
if err != nil {
    return err
}
if claims.Issuer != "https://idp.example.com" {
    return errors.New("wrong issuer")
}
if !claims.HasAudience("orders-api") {
    return errors.New("wrong audience")
}
```

Expected result: do not flag `TOKEX-AUD-04` when downstream services verify exact issuer and audience before accepting exchanged tokens.

