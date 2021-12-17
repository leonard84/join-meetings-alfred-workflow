.PHONY: clean build dist install

clean:
	cargo clean
	rm -rf dist

build:
	cargo build --release

dist: build
	mkdir -p dist
	cp -R workflow dist
	cp target/release/join-meetings-alfred-workflow dist/workflow/
	cd dist/workflow && strip join-meetings-alfred-workflow
	cd dist/workflow && zip ../join-meetings-alfred-workflow.alfredworkflow *


install: dist
	open dist/join-meetings-alfred-workflow.alfredworkflow
