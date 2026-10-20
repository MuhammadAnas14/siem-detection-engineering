# ---------------------------------------------------------------------------
# Splunk SIEM deployment - convenience targets over install/ and validation/.
#
# `make lint` runs anywhere with no Splunk installed and is the fast feedback
# loop while editing detection content.
# ---------------------------------------------------------------------------

SHELL := /bin/bash
SPLUNK_HOME ?= /opt/splunk
APP := siem_core

.PHONY: help
help:
	@echo "Splunk SIEM deployment"
	@echo
	@echo "  make env          create install/splunk.env from the example"
	@echo "  make lint         syntax-check every script, conf and dashboard"
	@echo "  make install      Splunk Enterprise + indexes + detection content"
	@echo "  make app          redeploy just the siem_core app"
	@echo "  make indexes      create and verify indexes"
	@echo "  make dbconnect    DB Connect database inputs"
	@echo "  make validate     post-deployment health check"
	@echo "  make simulate     fire inert test events to prove rules work"
	@echo "  make package      build a Splunkbase-style app tarball"
	@echo "  make clean        remove build artefacts"

install/splunk.env:
	@cp install/splunk.env.example install/splunk.env
	@chmod 600 install/splunk.env
	@echo "created install/splunk.env - edit it before deploying"

.PHONY: env
env: install/splunk.env

# ---------------------------------------------------------------------------
# Linting - runs anywhere, no Splunk required
# ---------------------------------------------------------------------------
.PHONY: lint lint-sh lint-xml lint-conf lint-csv
lint: lint-sh lint-xml lint-conf lint-csv
	@echo "lint: OK"

lint-sh:
	@echo "==> bash syntax"
	@for f in install/*.sh validation/*.sh forwarders/linux/bin/*.sh; do \
	    bash -n "$$f" || exit 1; \
	done
	@command -v shellcheck >/dev/null 2>&1 && { \
	    echo "==> shellcheck"; \
	    shellcheck -S warning -e SC1091,SC2086 install/*.sh validation/*.sh || true; \
	} || echo "    (shellcheck not installed, skipping)"

lint-xml:
	@echo "==> dashboard XML well-formedness"
	@for f in apps/$(APP)/default/data/ui/views/*.xml apps/$(APP)/default/data/ui/nav/*.xml; do \
	    python3 -c "import sys,xml.dom.minidom as m; m.parse(sys.argv[1])" "$$f" || exit 1; \
	done

lint-conf:
	@echo "==> conf file structure"
	@python3 scripts/lint_conf.py

lint-csv:
	@echo "==> lookup CSVs"
	@python3 -c "import csv,sys,glob; \
[sys.exit('ragged rows in '+f) for f in glob.glob('apps/$(APP)/lookups/*.csv') \
 if len({len(r) for r in csv.reader(open(f))}) != 1]"

# ---------------------------------------------------------------------------
# Deployment
# ---------------------------------------------------------------------------
.PHONY: install app indexes dbconnect
install: env
	sudo ./install/01_install_splunk_enterprise.sh
	sudo ./install/04_create_indexes.sh
	sudo ./install/05_deploy_app.sh

app: env lint
	sudo ./install/05_deploy_app.sh

indexes: env
	sudo ./install/04_create_indexes.sh

dbconnect: env
	sudo ./install/06_setup_dbconnect.sh

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
.PHONY: validate simulate verify-indexes
validate:
	sudo ./validation/validate_deployment.sh

simulate:
	sudo ./validation/simulate_attacks_linux.sh

verify-indexes:
	sudo ./install/04_create_indexes.sh --verify

# ---------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------
.PHONY: package
package: lint
	@mkdir -p dist
	tar --exclude='local' --exclude='local.meta' --exclude='*.pyc' \
	    -czf dist/$(APP)-1.0.0.tgz -C apps $(APP)
	@echo "built dist/$(APP)-1.0.0.tgz"
	@echo "install with: $(SPLUNK_HOME)/bin/splunk install app dist/$(APP)-1.0.0.tgz"

.PHONY: clean
clean:
	rm -rf dist
