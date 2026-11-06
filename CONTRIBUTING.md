# Contributing

Open an issue before a large change. This SDK stays limited to the send, status, download, and webhook calls in the pinned allowlist.

## Develop

Go 1.26 or newer is required.

```bash
GOWORK=off go test ./...
```

Keep line coverage and branch coverage each at or above 80% where the project measures both.

## Pull requests

Describe the caller-visible change in `CHANGELOG.md` when a caller would notice it. Do not add a dependency for a call the standard library already makes.

Report a vulnerability through [SECURITY.md](SECURITY.md). Do not open a public issue for it.

## License

By submitting a change, you agree that Signingflow may distribute it under the license in [LICENSE](LICENSE).
