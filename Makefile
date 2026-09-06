# Purpose: Developer convenience targets for build, test, compatibility verification, and cleanup.
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
	@printf '%s\n' 'repository verifier gate disabled per owner direction'

clean:
	rm -rf dist tools/__pycache__
