use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use axerrno::{AxError, AxResult};
use kbpf_basic::{linux_bpf::bpf_attr, map::BpfMapMeta};
use starry_api::{
    bpf::{
        map::{BpfMap, PollSetWrapper},
        tansform::{EbpfKernelAuxiliary, PerCpuImpl},
    },
    file::{add_file_like, get_file_like},
};

use crate::tansform::bpferror_to_axerr;

static SYSCALL_LIST_MAP_FD: AtomicU32 = AtomicU32::new(0);
static SYNC_TICKS: AtomicU32 = AtomicU32::new(0);

fn collect_syscall_counts_cb(key: &[u8], value: &[u8], ctx: *const u8) -> i32 {
    if key.len() != 4 || value.len() != 4 || ctx.is_null() {
        return 0;
    }

    let sysno = u32::from_ne_bytes(key.try_into().unwrap()) as usize;
    if sysno >= starry_vdso::vdso_ebpf_data::MAX_SYSNO {
        return 0;
    }

    let counts = unsafe { &mut *(ctx as *mut [u32; starry_vdso::vdso_ebpf_data::MAX_SYSNO]) };
    counts[sysno] = u32::from_ne_bytes(value.try_into().unwrap());
    0
}

/// Snapshot the `SYSCALL_LIST` map and publish it to the vDSO page.
pub fn sync_syscall_ebpf_fastpath() {
    let tick = SYNC_TICKS.fetch_add(1, Ordering::Relaxed);
    if tick % 10 != 0 {
        return;
    }

    let map_fd = SYSCALL_LIST_MAP_FD.load(Ordering::Acquire);
    if map_fd == 0 {
        return;
    }

    let Ok(file) = get_file_like(map_fd as _) else {
        return;
    };
    let Ok(bpf_map) = file.into_any().downcast::<BpfMap>() else {
        return;
    };

    let mut counts = [0u32; starry_vdso::vdso_ebpf_data::MAX_SYSNO];
    {
        let mut unified_map = bpf_map.unified_map();
        let map = unified_map.map_mut();
        let _ = map.for_each_elem(
            collect_syscall_counts_cb,
            (&mut counts as *mut _ as usize) as *const u8,
            0,
        );
    }

    starry_vdso::vdso::update_ebpf_data(&counts);
}

pub fn bpf_map_create(attr: &bpf_attr) -> AxResult<isize> {
    let map_meta = BpfMapMeta::try_from(attr).map_err(bpferror_to_axerr)?;
    axlog::debug!("The map attr is {:#?}", map_meta);
    let map_name = map_meta._map_name.clone();

    let poll_ready = Arc::new(PollSetWrapper::new());

    let unified_map = kbpf_basic::map::bpf_map_create::<EbpfKernelAuxiliary, PerCpuImpl>(
        map_meta,
        Some(poll_ready.clone()),
    )
    .map_err(bpferror_to_axerr);

    if let Err(e) = &unified_map {
        if e != &AxError::OperationNotSupported {
            axlog::error!("bpf_map_create: failed to create map: {:?}", e);
        }
    }

    let file = Arc::new(BpfMap::new(unified_map?, poll_ready));
    let fd = add_file_like(file.clone(), false).map(|fd| fd as _);
    if let Ok(fd) = fd {
        if map_name == "SYSCALL_LIST" {
            SYSCALL_LIST_MAP_FD.store(fd as u32, Ordering::Release);
        }
    }
    axlog::info!("bpf_map_create: fd: {:?}", fd);
    fd
}
