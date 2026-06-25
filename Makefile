# Purpose: Developer convenience targets (build/test/verify/clean) dispatching to tools/build.sh, tests/hardening.sh,
# and tools/verify.py.
# Role: tooling
# NOTE: Make uses '#' comments; place the header above the `.PHONY` line — it does not affect targets.

.PHONY: build test verify clean

IMAGE_REPOSITORY ?= ghcr.io/nwarila/ubi9-base-micro
RUNTIME_IMAGE ?= $(IMAGE_REPOSITORY):base-micro
DEV_IMAGE ?= $(IMAGE_REPOSITORY):base-micro-dev

build:
	bash tools/build.sh

test:
	bash tests/hardening.sh '$(RUNTIME_IMAGE)'

verify:
	python tools/verify.py

clean:
	rm -rf dist tools/__pycache__
