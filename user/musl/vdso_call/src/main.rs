use libc::{AT_SYSINFO_EHDR, c_ulong, getauxval};
use std::{env, eprintln, thread, time::Duration};

#[cfg(target_arch = "riscv64")]
const COUNTOFFSET: usize = 0x6fe;
#[cfg(target_arch = "riscv64")]
const SEQOFFSET: usize = 0x8d6;

type KvdsoGetSyscallCountFn = unsafe extern "C" fn(u32) -> u32;
type KvdsoSnapshotSeqFn = unsafe extern "C" fn() -> u64;

#[cfg(target_arch = "riscv64")]
fn read_counts_with_seq_check(
    sysnos: &[u32],
    get_count: KvdsoGetSyscallCountFn,
    snapshot_seq: KvdsoSnapshotSeqFn,
    max_retry: usize,
) -> Option<(u64, Vec<(u32, u32)>)> {
    for _ in 0..max_retry {
        let seq1 = unsafe { snapshot_seq() };
        if (seq1 & 1) != 0 {
            core::hint::spin_loop();
            continue;
        }

        let mut out = Vec::with_capacity(sysnos.len());
        for no in sysnos {
            let cnt = unsafe { get_count(*no) };
            out.push((*no, cnt));
        }

        let seq2 = unsafe { snapshot_seq() };
        if seq1 == seq2 {
            return Some((seq2, out));
        }
    }

    None
}

fn parse_sysnos() -> Vec<u32> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        // Common syscalls seen in the sample output.
        return vec![22, 64, 113];
    }

    let mut out = Vec::new();
    for arg in args {
        match arg.parse::<u32>() {
            Ok(v) => out.push(v),
            Err(_) => eprintln!("ignore invalid syscall number: {arg}"),
        }
    }
    if out.is_empty() {
        vec![22, 64, 113]
    } else {
        out
    }
}

fn resolve_vdso_base() -> Option<usize> {
    let vdso_base = unsafe { getauxval(AT_SYSINFO_EHDR as c_ulong) as usize };
    if vdso_base == 0 {
        return None;
    }

    Some(vdso_base)
}

#[cfg(target_arch = "riscv64")]
fn resolve_kvdso_funcs(vdso_base: usize) -> (KvdsoGetSyscallCountFn, KvdsoSnapshotSeqFn) {
    let count_addr = vdso_base.wrapping_add(COUNTOFFSET);
    let seq_addr = vdso_base.wrapping_add(SEQOFFSET);
    let get_count: KvdsoGetSyscallCountFn = unsafe { core::mem::transmute(count_addr) };
    let snapshot_seq: KvdsoSnapshotSeqFn = unsafe { core::mem::transmute(seq_addr) };
    (get_count, snapshot_seq)
}

fn main() {
    let Some(vdso_base) = resolve_vdso_base() else {
        eprintln!("AT_SYSINFO_EHDR not found, vDSO not available");
        return;
    };

    println!("vdso base = 0x{vdso_base:x}");

    #[cfg(target_arch = "riscv64")]
    {
        let (get_count, snapshot_seq) = resolve_kvdso_funcs(vdso_base);
        let sysnos = parse_sysnos();

        println!("kvdso_get_syscall_count addr = 0x{:x}", vdso_base + COUNTOFFSET);
        println!("kvdso_snapshot_seq addr = 0x{:x}", vdso_base + SEQOFFSET);
        println!("query syscalls: {:?}", sysnos);

        for round in 0..100 {
            match read_counts_with_seq_check(&sysnos, get_count, snapshot_seq, 32) {
                Some((seq, snapshot)) => {
                    println!("round {round}: seq={seq}");
                    for (no, cnt) in snapshot {
                        println!("  syscall {no}: {cnt}");
                    }
                }
                None => {
                    println!("round {round}: seq check failed after retries");
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
    }

    #[cfg(not(target_arch = "riscv64"))]
    {
        eprintln!("this test currently only provides function offsets for riscv64");
    }

}
