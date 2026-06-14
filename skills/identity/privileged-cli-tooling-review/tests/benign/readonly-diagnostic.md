# Benign: read-only diagnostic command

```go
func main() {
    status := diagnostics.ReadPublicHealth(args.Service)
    fmt.Println(status.Summary)
}
```

Expected result: do not flag privileged mutation controls for a read-only diagnostic that cannot access sensitive data or mutate state.

