# fips-shield — build, test, and install helpers.
#
#   make test         everything below (needs Docker; guard needs Linux)
#   make install      host-mode install of the whole stack
#
# Individual targets are listed by `make help`.

SHELL := /bin/bash
ENV ?= shield.env
PREFIX ?= /usr/local

# The guard is built as a static musl binary by default, because the same
# file has to run in two places: on the host (systemd) and inside the
# detection sidecar, which bind-mounts it (deploy/container/compose.guard.yaml).
# A glibc build links against the BUILD host's glibc, and glibc is backward
# compatible but never forward — so a binary built on a current distro
# will not exec in the debian:12-based sidecar, which fails at runtime with
# a GLIBC_x.yz loader error. Static removes the coupling entirely and works
# on any base image, including Alpine.
GUARD_TARGET ?= $(shell uname -m)-unknown-linux-musl
GUARD_BIN := guard/target/$(GUARD_TARGET)/release/fips-guard
GUARD_BIN_NATIVE := guard/target/release/fips-guard

.PHONY: help
help:
	@sed -n 's/^\([a-z-]*\):.*## \(.*\)/  \1\t\2/p' $(MAKEFILE_LIST) | expand -t22

.PHONY: images
images: ## build the shield and fail2ban container images
	docker build -f deploy/container/Dockerfile -t fips-shield .
	docker build -f deploy/container/Dockerfile.fail2ban -t fips-shield-f2b .

.PHONY: guard
guard: ## build the eBPF guard binary, static (Linux, needs clang)
	@rustup target list --installed 2>/dev/null | grep -qx '$(GUARD_TARGET)' || { \
	    echo "Rust target $(GUARD_TARGET) is not installed."; \
	    echo; \
	    echo "The guard is built static so ONE binary runs both on the host"; \
	    echo "and inside the detection sidecar, whose glibc is older than"; \
	    echo "most build hosts'. Install the target with:"; \
	    echo "    rustup target add $(GUARD_TARGET)"; \
	    echo; \
	    echo "If this host never runs the container-mode sidecar, a"; \
	    echo "host-only build works too: make guard-native"; \
	    exit 1; \
	}
	cargo build --release --target $(GUARD_TARGET) --manifest-path guard/Cargo.toml
	@echo "built $(GUARD_BIN)"

.PHONY: guard-native
guard-native: ## build the guard against the host's glibc (host-only deployments)
	cargo build --release --manifest-path guard/Cargo.toml
	@echo "built $(GUARD_BIN_NATIVE) — NOT portable into the sidecar;"
	@echo "use 'make guard' for container mode."

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

.PHONY: test-ws test-ban test-tcp test-http test-guard test-guard-sidecar test-filters
test-ws: ## behavioral: WebSocket message policy
	test/ws_smoke.sh
test-ban: ## behavioral: detection -> enforcement loop
	test/ban_smoke.sh
test-tcp: ## behavioral: generic TCP profile
	test/tcp_smoke.sh
test-http: ## behavioral: generic HTTP profile
	test/http_smoke.sh
test-guard: ## behavioral: eBPF guard (privileged, Linux)
	test/guard_smoke.sh
test-guard-sidecar: ## behavioral: containerized fail2ban banning via the guard's maps (Linux)
	test/guard_sidecar_smoke.sh
test-filters: ## detection: fail2ban filters match real log lines
	test/filters_test.sh

.PHONY: test
test: validate test-filters test-ws test-ban test-tcp test-http test-guard test-guard-sidecar ## run the full suite

.PHONY: install
install: ## host mode: render configs, install detection + guard (needs root)
	deploy/host/render.sh $(ENV)
	deploy/host/install-fail2ban.sh $(ENV)
	@echo
	@echo "nginx: run 'nginx -t && systemctl reload nginx'"
	@echo "guard: see guard/README.md to install the eBPF backend"

# install-guard deliberately does NOT depend on `guard`: it needs root,
# `guard` is a phony target whose recipe always runs, and a rustup
# toolchain lives in the invoking user's ~/.cargo/bin — outside sudo's
# secure_path. Rebuilding here would therefore fail under sudo
# ("cargo: command not found") or, worse, build as root.
# Build as your normal user, install as root.
.PHONY: install-guard
install-guard: ## install the eBPF guard and its systemd unit (run `make guard` first, needs root)
	@bin="$(GUARD_BIN)"; \
	[ -x "$$bin" ] || bin="$(GUARD_BIN_NATIVE)"; \
	test -x "$$bin" || { \
	    echo "no built guard binary found (looked in $(GUARD_BIN)"; \
	    echo "and $(GUARD_BIN_NATIVE))."; \
	    echo "Run 'make guard' as your normal user first (needs clang);"; \
	    echo "see guard/README.md for hosts without clang."; \
	    exit 1; \
	}; \
	if ! file -b "$$bin" | grep -q static; then \
	    echo "WARNING: $$bin is dynamically linked."; \
	    echo "  It will run on this host, but the container-mode detection"; \
	    echo "  sidecar bind-mounts this same file and its glibc is older,"; \
	    echo "  so it will fail there with a GLIBC_x.yz loader error."; \
	    echo "  Build a portable one with: make guard"; \
	fi; \
	install -m 755 "$$bin" $(PREFIX)/bin/fips-guard
	install -m 755 guard/shield-ban $(PREFIX)/bin/shield-ban
	install -d $(PREFIX)/lib/fips-shield
	install -m 755 core/actions/shield-ban $(PREFIX)/lib/fips-shield/shield-ban-file
	install -m 644 deploy/host/fips-guard.service /etc/systemd/system/
	install -m 644 deploy/host/fips-guard-watchdog.service /etc/systemd/system/
	install -m 644 deploy/host/fips-guard-watchdog.timer /etc/systemd/system/
	@echo "now: systemctl daemon-reload && systemctl enable --now fips-guard"
	@echo "     systemctl enable --now fips-guard-watchdog.timer"
	@echo "     (the timer re-attaches the classifier if it goes missing;"
	@echo "      without it, a detached filter is never noticed)"
