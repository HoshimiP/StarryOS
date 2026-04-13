use libc::{AT_SYSINFO_EHDR, c_ulong, getauxval};
#[cfg(target_arch = "riscv64")]
use std::{thread, time::Duration};

#[cfg(target_arch = "riscv64")]
const SCHED_BLOCKED_TICKS_OFFSET: usize = 0x780;
#[cfg(target_arch = "riscv64")]
const SCHED_CLASS_COUNT_OFFSET: usize = 0x79a;
#[cfg(target_arch = "riscv64")]
const SCHED_IDLE_TICKS_OFFSET: usize = 0x7c8;
#[cfg(target_arch = "riscv64")]
const SCHED_LAST_CPU_ID_OFFSET: usize = 0x7e2;
#[cfg(target_arch = "riscv64")]
const SCHED_LAST_TASK_STATE_OFFSET: usize = 0x7fe;
#[cfg(target_arch = "riscv64")]
const SCHED_LAST_TID_OFFSET: usize = 0x81a;
#[cfg(target_arch = "riscv64")]
const SCHED_LAST_UPDATE_NS_OFFSET: usize = 0x834;
#[cfg(target_arch = "riscv64")]
const SCHED_PRESSURE_SCORE_OFFSET: usize = 0x84e;
#[cfg(target_arch = "riscv64")]
const SCHED_RUNNABLE_TICKS_OFFSET: usize = 0x868;
#[cfg(target_arch = "riscv64")]
const SCHED_SNAPSHOT_SEQ_OFFSET: usize = 0x882;
#[cfg(target_arch = "riscv64")]
const SCHED_TICK_COUNT_OFFSET: usize = 0x8a2;
#[cfg(target_arch = "riscv64")]
const SCHED_TOTAL_SYSCALLS_OFFSET: usize = 0x8bc;

#[cfg(target_arch = "riscv64")]
const SCHED_CLASS_MAX: u32 = 4;

#[cfg(target_arch = "riscv64")]
type KvdsoSchedSnapshotSeqFn = unsafe extern "C" fn() -> u64;
#[cfg(target_arch = "riscv64")]
type KvdsoSchedBlockedTicksFn = unsafe extern "C" fn() -> u64;
#[cfg(target_arch = "riscv64")]
type KvdsoSchedClassCountFn = unsafe extern "C" fn(u32) -> u32;
#[cfg(target_arch = "riscv64")]
type KvdsoSchedIdleTicksFn = unsafe extern "C" fn() -> u64;
#[cfg(target_arch = "riscv64")]
type KvdsoSchedLastCpuIdFn = unsafe extern "C" fn() -> u32;
#[cfg(target_arch = "riscv64")]
type KvdsoSchedLastTaskStateFn = unsafe extern "C" fn() -> u32;
#[cfg(target_arch = "riscv64")]
type KvdsoSchedLastTidFn = unsafe extern "C" fn() -> u64;
#[cfg(target_arch = "riscv64")]
type KvdsoSchedLastUpdateNsFn = unsafe extern "C" fn() -> u64;
#[cfg(target_arch = "riscv64")]
type KvdsoSchedPressureScoreFn = unsafe extern "C" fn() -> u32;
#[cfg(target_arch = "riscv64")]
type KvdsoSchedRunnableTicksFn = unsafe extern "C" fn() -> u64;
#[cfg(target_arch = "riscv64")]
type KvdsoSchedTickCountFn = unsafe extern "C" fn() -> u64;
#[cfg(target_arch = "riscv64")]
type KvdsoSchedTotalSyscallsFn = unsafe extern "C" fn() -> u64;

#[cfg(target_arch = "riscv64")]
struct SchedFuncs {
    snapshot_seq: KvdsoSchedSnapshotSeqFn,
    blocked_ticks: KvdsoSchedBlockedTicksFn,
    class_count: KvdsoSchedClassCountFn,
    idle_ticks: KvdsoSchedIdleTicksFn,
    last_cpu_id: KvdsoSchedLastCpuIdFn,
    last_task_state: KvdsoSchedLastTaskStateFn,
    last_tid: KvdsoSchedLastTidFn,
    last_update_ns: KvdsoSchedLastUpdateNsFn,
    pressure_score: KvdsoSchedPressureScoreFn,
    runnable_ticks: KvdsoSchedRunnableTicksFn,
    tick_count: KvdsoSchedTickCountFn,
    total_syscalls: KvdsoSchedTotalSyscallsFn,
}

#[cfg(target_arch = "riscv64")]
#[derive(Debug)]
struct SchedSnapshot {
    seq: u64,
    blocked_ticks: u64,
    idle_ticks: u64,
    runnable_ticks: u64,
    tick_count: u64,
    total_syscalls: u64,
    pressure_score: u32,
    last_cpu_id: u32,
    last_task_state: u32,
    last_tid: u64,
    last_update_ns: u64,
    class_hist: [u32; SCHED_CLASS_MAX as usize],
}

fn resolve_vdso_base() -> Option<usize> {
    let vdso_base = unsafe { getauxval(AT_SYSINFO_EHDR as c_ulong) as usize };
    if vdso_base == 0 {
        return None;
    }
    Some(vdso_base)
}

#[cfg(target_arch = "riscv64")]
fn resolve_sched_funcs(vdso_base: usize) -> SchedFuncs {
    SchedFuncs {
        snapshot_seq: unsafe { core::mem::transmute(vdso_base.wrapping_add(SCHED_SNAPSHOT_SEQ_OFFSET)) },
        blocked_ticks: unsafe { core::mem::transmute(vdso_base.wrapping_add(SCHED_BLOCKED_TICKS_OFFSET)) },
        class_count: unsafe { core::mem::transmute(vdso_base.wrapping_add(SCHED_CLASS_COUNT_OFFSET)) },
        idle_ticks: unsafe { core::mem::transmute(vdso_base.wrapping_add(SCHED_IDLE_TICKS_OFFSET)) },
        last_cpu_id: unsafe { core::mem::transmute(vdso_base.wrapping_add(SCHED_LAST_CPU_ID_OFFSET)) },
        last_task_state: unsafe { core::mem::transmute(vdso_base.wrapping_add(SCHED_LAST_TASK_STATE_OFFSET)) },
        last_tid: unsafe { core::mem::transmute(vdso_base.wrapping_add(SCHED_LAST_TID_OFFSET)) },
        last_update_ns: unsafe { core::mem::transmute(vdso_base.wrapping_add(SCHED_LAST_UPDATE_NS_OFFSET)) },
        pressure_score: unsafe { core::mem::transmute(vdso_base.wrapping_add(SCHED_PRESSURE_SCORE_OFFSET)) },
        runnable_ticks: unsafe { core::mem::transmute(vdso_base.wrapping_add(SCHED_RUNNABLE_TICKS_OFFSET)) },
        tick_count: unsafe { core::mem::transmute(vdso_base.wrapping_add(SCHED_TICK_COUNT_OFFSET)) },
        total_syscalls: unsafe { core::mem::transmute(vdso_base.wrapping_add(SCHED_TOTAL_SYSCALLS_OFFSET)) },
    }
}

#[cfg(target_arch = "riscv64")]
fn read_sched_snapshot_with_seq_check(funcs: &SchedFuncs, max_retry: usize) -> Option<SchedSnapshot> {
    for _ in 0..max_retry {
        let seq1 = unsafe { (funcs.snapshot_seq)() };
        if (seq1 & 1) != 0 {
            core::hint::spin_loop();
            continue;
        }

        let mut class_hist = [0u32; SCHED_CLASS_MAX as usize];
        let mut class = 0;
        while class < SCHED_CLASS_MAX {
            class_hist[class as usize] = unsafe { (funcs.class_count)(class) };
            class += 1;
        }

        let snapshot = SchedSnapshot {
            seq: seq1,
            blocked_ticks: unsafe { (funcs.blocked_ticks)() },
            idle_ticks: unsafe { (funcs.idle_ticks)() },
            runnable_ticks: unsafe { (funcs.runnable_ticks)() },
            tick_count: unsafe { (funcs.tick_count)() },
            total_syscalls: unsafe { (funcs.total_syscalls)() },
            pressure_score: unsafe { (funcs.pressure_score)() },
            last_cpu_id: unsafe { (funcs.last_cpu_id)() },
            last_task_state: unsafe { (funcs.last_task_state)() },
            last_tid: unsafe { (funcs.last_tid)() },
            last_update_ns: unsafe { (funcs.last_update_ns)() },
            class_hist,
        };

        let seq2 = unsafe { (funcs.snapshot_seq)() };
        if seq1 == seq2 {
            return Some(snapshot);
        }
    }

    None
}

#[cfg(target_arch = "riscv64")]
fn task_state_name(state: u32) -> &'static str {
    match state {
        1 => "running",
        2 => "ready",
        3 => "blocked",
        4 => "exited",
        _ => "unknown",
    }
}

fn main() {
    let Some(vdso_base) = resolve_vdso_base() else {
        eprintln!("AT_SYSINFO_EHDR not found, vDSO not available");
        return;
    };

    println!("vdso base = 0x{vdso_base:x}");

    #[cfg(target_arch = "riscv64")]
    {
        let funcs = resolve_sched_funcs(vdso_base);

        println!("kvdso_sched_snapshot_seq addr = 0x{:x}", vdso_base + SCHED_SNAPSHOT_SEQ_OFFSET);
        println!("kvdso_sched_pressure_score addr = 0x{:x}", vdso_base + SCHED_PRESSURE_SCORE_OFFSET);
        println!("kvdso_sched_last_tid addr = 0x{:x}", vdso_base + SCHED_LAST_TID_OFFSET);

        for round in 0..100 {
            match read_sched_snapshot_with_seq_check(&funcs, 64) {
                Some(s) => {
                    println!("round {round}: seq={}", s.seq);
                    println!(
                        "  tick={} runnable={} blocked={} idle={} total_syscalls={} pressure={}",
                        s.tick_count, s.runnable_ticks, s.blocked_ticks, s.idle_ticks, s.total_syscalls, s.pressure_score
                    );
                    println!(
                        "  last: tid={} cpu={} state={}({}) update_ns={}",
                        s.last_tid,
                        s.last_cpu_id,
                        s.last_task_state,
                        task_state_name(s.last_task_state),
                        s.last_update_ns
                    );
                    println!(
                        "  class_hist: other={} io_wait={} sleep_wait={} sync_wait={}",
                        s.class_hist[0], s.class_hist[1], s.class_hist[2], s.class_hist[3]
                    );
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
