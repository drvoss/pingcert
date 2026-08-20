# Contributing to pingcert

Bug reports and focused pull requests are welcome. Please do not include real
certificates, private hostnames, credentials, or internal network addresses in
issues or test fixtures.

Before submitting a pull request, run:

```sh
gofmt -w .
go vet ./...
go test ./...
```

Describe the platform you tested and include a regression test for behavior
changes. Network-dependent tests should use local test servers or injected
fakes so that the suite remains deterministic. By contributing, you agree that
your contribution is licensed under the MIT License.
