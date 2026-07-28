# fips-shield — build, test, and install helpers.
#
#   make test         everything below (needs Docker; guard needs Linux)
#   make install      host-mode install of the whole stack
#
# Individual targets are listed by `make help`.

SHELL := /bin/bash
ENV ?= shield.env
PREFIX ?= /usr/local

.PHONY: help
help:
	@sed -n 's/^\([a-z-]*\):.*## \(.*\)/  \1\t\2/p' $(MAKEFILE_LIST) | expand -t22

.PHONY: images
images: ## build the shield and fail2ban container images
	docker build -f deploy/container/Dockerfile -t fips-shield .
	docker build -f deploy/container/Dockerfile.fail2ban -t fips-shield-f2b .

.PHONY: guard
guard: ## build the eBPF guard binary (Linux, needs clang)
	cargo build --release --manifest-path guard/Cargo.toml

.PHONY: lint
lint: ## shellcheck + rustfmt + clippy
	# SC2016 is excluded: the literal $${VAR} lists handed to envsubst,
	# and the grep/printf patterns that build them, must not expand.
	# Falls back to the shellcheck image when the binary is not installed.
	@files="$$(git ls-files '*.sh') core/actions/shield-ban guard/shield-ban"; \
	if command -v shellcheck >/dev/null; then \
	    shellcheck --exclude=SC2016 $$files; \
	else \
	    docker run --rm -v "$$PWD":/mnt -w /mnt koalaman/shellcheck:stable \
	        --exclude=SC2016 $$files; \
	fi
	cargo fmt --manifest-path guard/Cargo.toml --check
	cargo clippy --manifest-path guard/Cargo.toml --all-targets -- -D warnings

.PHONY: validate
validate: ## static: render every profile, nginx -t, fail2ban -t
	test/validate.sh

.PHONY: test-ws test-ban test-tcp test-guard
test-ws: ## behavioral: WebSocket message policy
	test/ws_smoke.sh
test-ban: ## behavioral: detection -> enforcement loop
	test/ban_smoke.sh
test-tcp: ## behavioral: generic TCP profile
	test/tcp_smoke.sh
test-guard: ## behavioral: eBPF guard (privileged, Linux)
	test/guard_smoke.sh

.PHONY: test
test: validate test-ws test-ban test-tcp test-guard ## run the full suite

.PHONY: install
install: ## host mode: render configs, install detection + guard (needs root)
	deploy/host/render.sh $(ENV)
	deploy/host/install-fail2ban.sh $(ENV)
	@echo
	@echo "nginx: run 'nginx -t && systemctl reload nginx'"
	@echo "guard: see guard/README.md to install the eBPF backend"

.PHONY: install-guard
install-guard: guard ## install the eBPF guard and its systemd unit (needs root)
	install -m 755 guard/target/release/fips-guard $(PREFIX)/bin/fips-guard
	install -m 755 guard/shield-ban $(PREFIX)/bin/shield-ban
	install -d $(PREFIX)/lib/fips-shield
	install -m 755 core/actions/shield-ban $(PREFIX)/lib/fips-shield/shield-ban-file
	install -m 644 deploy/host/fips-guard.service /etc/systemd/system/
	@echo "now: systemctl daemon-reload && systemctl enable --now fips-guard"
