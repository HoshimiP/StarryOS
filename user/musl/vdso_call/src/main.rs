use libc::{c_ulong, clockid_t, getauxval, timespec, AT_SYSINFO_EHDR, CLOCK_MONOTONIC};
use std::{eprintln, println};

#[cfg(target_arch = "riscv64")]
const CLOCK_GETTIME_SYM_OFFSET: usize = 0x5fe;

type VdsoClockGettimeFn = unsafe extern "C" fn(clockid: clockid_t, tp: *mut timespec) -> i32;

fn resolve_vdso_clock_gettime() -> Option<(usize, VdsoClockGettimeFn)> {
    let vdso_base = unsafe { getauxval(AT_SYSINFO_EHDR as c_ulong) as usize };
    if vdso_base == 0 {
        return None;
    }

    let addr = vdso_base.wrapping_add(CLOCK_GETTIME_SYM_OFFSET);
    let func: VdsoClockGettimeFn = unsafe { core::mem::transmute(addr) };
    Some((vdso_base, func))
}

fn main() {
    let Some((vdso_base, vdso_clock_gettime)) = resolve_vdso_clock_gettime() else {
        eprintln!("AT_SYSINFO_EHDR not found, vDSO not available");
        return;
    };

    println!("vdso base = 0x{vdso_base:x}");
    println!("__vdso_clock_gettime addr = 0x{:x}", vdso_base + CLOCK_GETTIME_SYM_OFFSET);

    let mut ts_vdso = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    let vdso_ret = unsafe { vdso_clock_gettime(CLOCK_MONOTONIC, &mut ts_vdso as *mut _) };
    println!(
        "vDSO clock_gettime ret={}, tv_sec={}, tv_nsec={}",
        vdso_ret, ts_vdso.tv_sec, ts_vdso.tv_nsec
    );

    let mut ts_libc = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let libc_ret = unsafe { libc::clock_gettime(CLOCK_MONOTONIC, &mut ts_libc as *mut _) };
    println!(
        "libc clock_gettime ret={}, tv_sec={}, tv_nsec={}",
        libc_ret, ts_libc.tv_sec, ts_libc.tv_nsec
    );
}
