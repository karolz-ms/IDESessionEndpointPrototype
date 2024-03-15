.DEFAULT_GOAL := help

ifneq (3.81,$(firstword $(sort $(MAKE_VERSION) 3.81)))
    $(error This Makefile requires make version 3.81 or newer. You have make version $(MAKE_VERSION))
endif

# Detect the operating system, and configure shell and shell commands.
ifeq ($(OS),Windows_NT)
    detected_OS := Windows
	SHELL := pwsh.exe
	.SHELLFLAGS := -Command
	repo_dir := $(shell Get-Location | Select-Object -ExpandProperty Path)
	exe_suffix := .exe
	mkdir := New-Item -ItemType Directory -Force -Path
	rm_rf := Remove-Item -Recurse -Force -Path
else
    # -o pipefail will treat a pipeline as failed if one of the elements fail.
    SHELL := /usr/bin/env bash -o pipefail

    detected_OS := $(shell uname -s)
	repo_dir := $(shell pwd)
	exe_suffix :=
	mkdir := mkdir -p
	rm_rf := rm -rf
endif

## Environment variables affecting build
# Note these have to be defined before they are used in targets

ifeq ($(detected_OS),Windows)
    GO_SOURCES := $(shell Get-ChildItem -Include '*.go' -Recurse -File | Select-Object -ExpandProperty FullName | Select-String -NotMatch 'external','pkg\\generated')
else
    GO_SOURCES := $(shell find . -name '*.go' -type f -not -path "./external/*" -not -path "./pkg/generated/*")
endif

OUTPUT_BIN ?= $(repo_dir)/bin
CLIENT_EXE ?= $(OUTPUT_BIN)/client-go$(exe_suffix)
TOOL_BIN ?= $(repo_dir)/.toolbin
GOLANGCI_LINT ?= $(TOOL_BIN)/golangci-lint$(exe_suffix)

# Tool versions
GOLANGCI_LINT_VERSION ?= v1.51.2


# Disable C interop https://dave.cheney.net/2016/01/18/cgo-is-not-go
export CGO_ENABLED=0


##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: build
build: $(CLIENT_EXE) ## Build the program executable
$(CLIENT_EXE): $(GO_SOURCES) go.mod | $(OUTPUT_BIN)
	go build -o $(CLIENT_EXE)

.PHONY: lint
lint: golangci-lint ## Runs linter.
# On Windows we use the global golangci-lint binary.
ifeq ($(detected_OS),Windows)
	golangci-lint run --timeout 5m
else
	$(GOLANGCI_LINT) run --timeout 5m
endif

.PHONY: clean
clean: ## Delete build output (client-go program executable)
	$(rm_rf) $(OUTPUT_BIN)/*
	$(rm_rf) $(TOOL_BIN)/*

.PHONY: run
run: build ## Run the program
	$(CLIENT_EXE) -s localhost:5213


## Development support targets

${OUTPUT_BIN}:
	@$(mkdir) ${OUTPUT_BIN}

$(TOOL_BIN):
	@$(mkdir) $(TOOL_BIN)

.PHONY: golangci-lint
ifeq ($(detected_OS),Windows)
# golangci-lint does not have pwsh-compatible install script, so the user must install it manually
golangci-lint:
	@ try { golangci-lint --version } catch { Write-Error "golangci-lint tool is missing. See https://golangci-lint.run/usage/install/#local-installation for installation instructions." }
else
golangci-lint: $(GOLANGCI_LINT)
$(GOLANGCI_LINT): | $(TOOL_BIN)
	[[ -s $(GOLANGCI_LINT) ]] || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TOOL_BIN) $(GOLANGCI_LINT_VERSION)
endif

