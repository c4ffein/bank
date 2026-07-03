.PHONY: help
.PHONY: lint-check test verify install-build-system build-package install-package-uploader upload-package-test upload-package

help:
	@echo "Available commands:"
	@echo "  lint-check"
	@echo "  test"
	@echo "  verify"
	@echo "  install-build-system"
	@echo "  build-package"
	@echo "  install-package-uploader"
	@echo "  upload-package-test"
	@echo "  upload-package"

lint:
	uvx ruff@0.5.1 check --fix; uvx ruff@0.5.1 format

lint-check:
	uvx ruff@0.5.1 check --no-fix && uvx ruff@0.5.1 format --check

test:
	python3 test.py

verify: lint-check test

fast-validate:
	uvx ruff@0.5.1 check --fix && uvx ruff@0.5.1 format && make test

install-build-system:
	python3 -m pip install --upgrade build

build-package:
	python3 -m build --sdist

install-package-uploader:
	python3 -m pip install --upgrade twine

upload-package-test:
	python3 -m twine upload --repository testpypi --verbose dist/*

upload-package:
	python3 -m twine upload --verbose dist/*
