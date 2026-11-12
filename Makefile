# Makefile for zen5-scheduler (Rust + eBPF sched_ext + Ring-0 LKM)

.PHONY: all rust kmod test install verify clean

all: rust kmod

rust:
	cargo build --release
	mkdir -p bin
	cp -f target/release/zen5 bin/zen5

kmod:
	$(MAKE) -C kmod
	mkdir -p bin
	cp kmod/zen5_entropy_kmod.ko bin/zen5_entropy_kmod.ko

test:
	cargo test

install: all
	./bin/zen5 install

verify:
	./bin/zen5 verify-install

clean:
	cargo clean
	$(MAKE) -C kmod clean
	rm -f bin/zen5 bin/scx_ryzen350.bpf.o bin/zen5_entropy_kmod.ko
