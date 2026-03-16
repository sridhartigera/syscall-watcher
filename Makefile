# Syscall Watcher — eBPF syscall tracer
# Build pattern follows calico's BPF compilation (clang -target bpf + CO-RE)

CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL    ?= bpftool
ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

VMLINUX_H  := bpf/vmlinux.h
BPF_SRC    := bpf/syscall_watcher.bpf.c
BPF_OBJ    := bpf/syscall_watcher.bpf.o

POLICY_SRC := bpf/syscall_policy.bpf.c
POLICY_OBJ := bpf/syscall_policy.bpf.o

PIN_DIR    := /sys/fs/bpf/syscall_watcher
POLICY_PIN := /sys/fs/bpf/syscall_policy

POLICY_FILE ?=

# Helper: find BPF map ID by name (run at recipe time, not parse time)
FIND_MAP = $$($(BPFTOOL) map show --json 2>/dev/null | \
	python3 -c "import sys,json; ms=json.load(sys.stdin); print(next((m['id'] for m in ms if m.get('name')=='$(1)'),''))" 2>/dev/null)

# Helper: encode a u64 as 8-byte little-endian hex
U64_HEX = $$(python3 -c "v=$(1); print(' '.join(f'{(v>>(i*8))&0xff:02x}' for i in range(8)))")

.PHONY: all clean vmlinux load unload watch summary detect policy-load policy-unload policy-summary

all: $(BPF_OBJ) $(POLICY_OBJ)

$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

vmlinux: $(VMLINUX_H)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H)
	$(CLANG) -g -O2 \
		-target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		-I bpf/ \
		-c $(BPF_SRC) \
		-o $@
	$(LLVM_STRIP) -g $@

$(POLICY_OBJ): $(POLICY_SRC) $(VMLINUX_H)
	$(CLANG) -g -O2 \
		-target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		-I bpf/ \
		-c $(POLICY_SRC) \
		-o $@
	$(LLVM_STRIP) -g $@

# Usage:
#   sudo make load PID=<pid>                          # trace a process
#   sudo make load CONTAINER=<id_or_name>             # trace a container
#   sudo make load PID=<pid> FILTER=network           # trace only network syscalls
#   sudo make load CONTAINER=<id> FILTER=minimal      # minimal tracing for a container
PID             ?= 0
CONTAINER       ?=
FOLLOW_CHILDREN ?= 1
FILTER          ?= default

load: $(BPF_OBJ)
	@if [ "$(PID)" = "0" ] && [ -z "$(CONTAINER)" ]; then \
		echo "Usage:"; \
		echo "  sudo make load PID=<pid>              # trace a process"; \
		echo "  sudo make load CONTAINER=<id_or_name> # trace a container"; \
		echo ""; \
		echo "Options:"; \
		echo "  FILTER=default|minimal|file|network|all"; \
		echo "  FOLLOW_CHILDREN=1|0"; \
		exit 1; \
	fi
	@mkdir -p $(PIN_DIR)
	$(BPFTOOL) prog loadall $(BPF_OBJ) $(PIN_DIR) autoattach
	@echo "==> Programs loaded and attached"
	@# Find config map
	MAP_ID=$(call FIND_MAP,watcher_config); \
	if [ -z "$$MAP_ID" ]; then \
		echo "ERROR: Could not find watcher_config map"; exit 1; \
	fi; \
	if [ -n "$(CONTAINER)" ]; then \
		echo "==> Resolving container '$(CONTAINER)' to cgroup ID"; \
		CGID=$$(./resolve_container.sh "$(CONTAINER)"); \
		if [ -z "$$CGID" ]; then \
			echo "ERROR: Could not resolve container"; exit 1; \
		fi; \
		echo "==> Targeting cgroup ID $$CGID"; \
		$(BPFTOOL) map update id $$MAP_ID \
			key hex 02 00 00 00 \
			value hex $(call U64_HEX,$$CGID); \
	fi; \
	if [ "$(PID)" != "0" ]; then \
		echo "==> Setting target PID=$(PID)"; \
		$(BPFTOOL) map update id $$MAP_ID \
			key hex 00 00 00 00 \
			value hex $(call U64_HEX,$(PID)); \
	fi; \
	$(BPFTOOL) map update id $$MAP_ID \
		key hex 01 00 00 00 \
		value hex 0$(FOLLOW_CHILDREN) 00 00 00 00 00 00 00
	@# Populate syscall names
	NAMES_ID=$(call FIND_MAP,syscall_names); \
	if [ -n "$$NAMES_ID" ]; then \
		echo "==> Populating syscall names"; \
		./populate_syscall_names.sh $$NAMES_ID; \
	fi
	@# Populate syscall filter
	FILTER_ID=$(call FIND_MAP,syscall_filter); \
	if [ -n "$$FILTER_ID" ]; then \
		./populate_syscall_filter.sh $$FILTER_ID $(FILTER); \
	fi
	@echo "==> Ready! Run: sudo make watch"

unload:
	@echo "==> Unloading BPF programs"
	rm -rf $(PIN_DIR)
	@echo "==> Done"

watch:
	cat /sys/kernel/debug/tracing/trace_pipe

# Cumulative stats summary, refreshes every INTERVAL seconds
INTERVAL ?= 5
summary:
	./summary.sh $(INTERVAL)

# AI agent detection scoring
DETECT_SAMPLES  ?= 10
DETECT_INTERVAL ?= 3
detect:
	./detect_agent.sh --samples $(DETECT_SAMPLES) --interval $(DETECT_INTERVAL)

# Usage:
#   sudo make policy-load PID=<pid> POLICY_FILE=policies/no-network.policy
#   sudo make policy-load CONTAINER=<id> POLICY_FILE=policies/protect-system.policy
policy-load: $(POLICY_OBJ)
	@if [ -z "$(POLICY_FILE)" ]; then \
		echo "Usage:"; \
		echo "  sudo make policy-load PID=<pid> POLICY_FILE=<file>"; \
		echo "  sudo make policy-load CONTAINER=<id> POLICY_FILE=<file>"; \
		echo ""; \
		echo "Built-in policies:"; \
		echo "  policies/no-network.policy    — block all network ops"; \
		echo "  policies/no-exec.policy       — block exec"; \
		echo "  policies/read-only-fs.policy  — block fs writes"; \
		echo "  policies/protect-system.policy — protect /etc /usr /boot"; \
		exit 1; \
	fi
	@if [ "$(PID)" = "0" ] && [ -z "$(CONTAINER)" ]; then \
		echo "ERROR: Must specify PID=<pid> or CONTAINER=<id>"; \
		exit 1; \
	fi
	@mkdir -p $(POLICY_PIN)
	$(BPFTOOL) prog loadall $(POLICY_OBJ) $(POLICY_PIN) autoattach
	@echo "==> Policy programs loaded and attached"
	@# Configure target PID / cgroup
	MAP_ID=$(call FIND_MAP,policy_config); \
	if [ -z "$$MAP_ID" ]; then \
		echo "ERROR: Could not find policy_config map"; exit 1; \
	fi; \
	if [ -n "$(CONTAINER)" ]; then \
		echo "==> Resolving container '$(CONTAINER)' to cgroup ID"; \
		CGID=$$(./resolve_container.sh "$(CONTAINER)"); \
		if [ -z "$$CGID" ]; then \
			echo "ERROR: Could not resolve container"; exit 1; \
		fi; \
		echo "==> Targeting cgroup ID $$CGID"; \
		$(BPFTOOL) map update id $$MAP_ID \
			key hex 02 00 00 00 \
			value hex $(call U64_HEX,$$CGID); \
	fi; \
	if [ "$(PID)" != "0" ]; then \
		echo "==> Setting target PID=$(PID)"; \
		$(BPFTOOL) map update id $$MAP_ID \
			key hex 00 00 00 00 \
			value hex $(call U64_HEX,$(PID)); \
	fi; \
	$(BPFTOOL) map update id $$MAP_ID \
		key hex 01 00 00 00 \
		value hex 0$(FOLLOW_CHILDREN) 00 00 00 00 00 00 00
	@# Populate policy maps
	@echo "==> Loading policy from $(POLICY_FILE)"
	POLICY_ID=$(call FIND_MAP,policy_map); \
	PATHS_ID=$(call FIND_MAP,policy_protected_paths); \
	PATH_OPS_ID=$(call FIND_MAP,policy_path_ops); \
	PATH_COUNT_ID=$(call FIND_MAP,policy_path_count); \
	./populate_policy.sh "$$POLICY_ID" "$$PATHS_ID" "$$PATH_OPS_ID" "$$PATH_COUNT_ID" "$(POLICY_FILE)"
	@echo "==> Policy active! Denied ops logged to: sudo make watch"

policy-unload:
	@echo "==> Unloading policy programs"
	rm -rf $(POLICY_PIN)
	@echo "==> Done"

policy-summary:
	./policy_summary.sh

clean:
	rm -f $(BPF_OBJ) $(POLICY_OBJ) $(VMLINUX_H)
