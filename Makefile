# Syscall Watcher — eBPF syscall tracer
# Build pattern follows calico's BPF compilation (clang -target bpf + CO-RE)

CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL    ?= bpftool
ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

VMLINUX_H  := bpf/vmlinux.h
BPF_SRC    := bpf/syscall_watcher.bpf.c
BPF_OBJ    := bpf/syscall_watcher.bpf.o

PIN_DIR    := /sys/fs/bpf/syscall_watcher

# Helper: find BPF map ID by name (run at recipe time, not parse time)
FIND_MAP = $$($(BPFTOOL) map show --json 2>/dev/null | \
	python3 -c "import sys,json; ms=json.load(sys.stdin); print(next((m['id'] for m in ms if m.get('name')=='$(1)'),''))" 2>/dev/null)

# Helper: encode a u64 as 8-byte little-endian hex
U64_HEX = $$(python3 -c "v=$(1); print(' '.join(f'{(v>>(i*8))&0xff:02x}' for i in range(8)))")

.PHONY: all clean vmlinux load unload watch summary

all: $(BPF_OBJ)

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

clean:
	rm -f $(BPF_OBJ) $(VMLINUX_H)
