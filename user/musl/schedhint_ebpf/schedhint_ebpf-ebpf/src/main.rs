#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{kprobe, map},
    maps::HashMap,
    programs::ProbeContext,
};
use schedhint_ebpf_common::{CLASS_IO_WAIT, CLASS_OTHER, CLASS_SLEEP_WAIT, CLASS_SYNC_WAIT};

#[kprobe]
pub fn schedhint_ebpf(ctx: ProbeContext) -> u32 {
    try_schedhint_ebpf(ctx).unwrap_or_else(|ret| ret)
}

#[cfg(feature = "riscv64")]
pub fn get_arg0(ctx: &ProbeContext) -> u64 {
    let pt_regs = unsafe { &*ctx.regs };
    pt_regs.a0 as u64
}

#[cfg(feature = "x86_64")]
pub fn get_arg0(cxt: &ProbeContext) -> u64 {
    // first arg -> rdi
    // second arg -> rsi
    // third arg -> rdx
    // four arg -> rcx
    let pt_regs = unsafe { &*cxt.regs };
    pt_regs.rdi as u64
}

#[cfg(feature = "loongarch64")]
pub fn get_arg0(ctx: &ProbeContext) -> u64 {
    let pt_regs = unsafe { &*ctx.regs };
    pt_regs.regs[4] as u64
}

#[cfg(feature = "aarch64")]
pub fn get_arg0(ctx: &ProbeContext) -> u64 {
    let pt_regs = unsafe { &*ctx.regs };
    pt_regs.regs[0] as u64
}

fn try_schedhint_ebpf(ctx: ProbeContext) -> Result<u32, u32> {
    let syscall_num = get_arg0(&ctx) as u32;
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let (class, weight) = classify_syscall(syscall_num);

    let _ = ctx;
    inc_u32(&SYSCALL_TOTAL, syscall_num, 1);
    inc_u32(&SYSCALL_BLOCKING_SCORE, syscall_num, weight);
    set_u64(&SYSCALL_LAST_SEEN_NS, syscall_num, now_ns);
    inc_u32(&SYSCALL_CLASS_HIST, class, 1);

    Ok(0)
}

#[inline(always)]
fn classify_syscall(sysno: u32) -> (u32, u32) {
    match sysno {
        // read/pread/readv/recvfrom/recvmsg/epoll_wait/ppoll/select
        63 | 67 | 65 | 207 | 212 | 22 | 73 | 23 => (CLASS_IO_WAIT, 3),
        // nanosleep/clock_nanosleep/sched_yield
        101 | 115 | 124 => (CLASS_SLEEP_WAIT, 2),
        // futex
        98 => (CLASS_SYNC_WAIT, 4),
        _ => (CLASS_OTHER, 1),
    }
}

#[inline(always)]
fn inc_u32(map: &HashMap<u32, u32>, key: u32, delta: u32) {
    let next = unsafe { map.get(&key).copied().unwrap_or(0) }.saturating_add(delta);
    let _ = map.insert(&key, &next, 0);
}

#[inline(always)]
fn set_u64(map: &HashMap<u32, u64>, key: u32, value: u64) {
    let _ = map.insert(&key, &value, 0);
}

#[map]
static SYSCALL_TOTAL: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[map]
static SYSCALL_BLOCKING_SCORE: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[map]
static SYSCALL_LAST_SEEN_NS: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(1024, 0);

#[map]
static SYSCALL_CLASS_HIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(16, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // we need use this because the verifier will forbid loop
    unsafe { core::hint::unreachable_unchecked() }
    // loop{}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
