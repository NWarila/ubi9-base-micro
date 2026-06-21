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
