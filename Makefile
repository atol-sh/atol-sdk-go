.PHONY: ci-local

ci-local:
	@test -z "$$(git status --porcelain)" || { echo 'working tree must be clean' >&2; exit 1; }
	GOWORK=off go mod verify
	GOWORK=off go build ./...
	GOWORK=off go vet ./...
	GOWORK=off go test -race -count=1 -timeout=120s ./...
	GOWORK=off govulncheck ./...
	GOWORK=off go-licenses check ./... \
		--ignore=atol.sh/sdk-go \
		--allowed_licenses=Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,BSD-2-Clause-FreeBSD,BSD-2-Clause-Views,ISC,Unicode-3.0,CDLA-Permissive-2.0,Zlib
	@set -eu; for entry in \
		.:FuzzParseJWTToken .:FuzzValidateTokenDoesNotPanic \
		.:FuzzNormalizeDPoPURI .:FuzzReconstructRequestURI \
		.:FuzzDPoPValidate policy/engine:FuzzLoadBundle \
		hmac:FuzzVerifiedStreamBody zanzibar/model:FuzzCompile; do \
		pkg=$${entry%%:*}; target=$${entry#*:}; \
		GOWORK=off go test -run='^$$' -fuzz="^$${target}$$" -fuzztime=30s "./$${pkg}"; \
	done
	buf generate
	@git diff --exit-code -- gen/ && git diff --cached --exit-code -- gen/
	@test -z "$$(git status --porcelain)" || { echo 'working tree changed during ci-local' >&2; exit 1; }
	@git rev-parse HEAD > "$$(git rev-parse --git-path ci-local-pass)"
