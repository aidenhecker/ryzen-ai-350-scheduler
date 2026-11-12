use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/scx_ryzen350.bpf.c");
    println!("cargo:rerun-if-changed=src/scx_ryzen350.h");

    // Detect running kernel version for vmlinux.h & libbpf headers
    let uname = Command::new("uname")
        .arg("-r")
        .output()
        .expect("Failed to execute uname -r");
    let kver = String::from_utf8_lossy(&uname.stdout).trim().to_string();
    let kdir = format!("/usr/src/kernels/{}", kver);
    let bpf_inc = format!("{}/tools/bpf/resolve_btfids/libbpf/include", kdir);

    let _ = std::fs::create_dir_all("bin");

    if Path::new(&kdir).exists() && Path::new("src/scx_ryzen350.bpf.c").exists() {
        let status = Command::new("clang")
            .args([
                "-g",
                "-O2",
                "-target",
                "bpf",
                "-Wno-missing-declarations",
                "-D__TARGET_ARCH_x86",
                &format!("-I{}", kdir),
                &format!("-I{}", bpf_inc),
                "-Isrc",
                "-c",
                "src/scx_ryzen350.bpf.c",
                "-o",
                "bin/scx_ryzen350.bpf.o",
            ])
            .status()
            .expect("Failed to invoke clang for BPF compilation");

        if !status.success() {
            panic!("Failed to compile src/scx_ryzen350.bpf.c");
        }
    }

    // Link against system libbpf.so.1, libelf, and libz
    println!("cargo:rustc-link-arg=/usr/lib64/libbpf.so.1");
    println!("cargo:rustc-link-lib=elf");
    println!("cargo:rustc-link-lib=z");
}
