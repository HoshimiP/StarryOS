use alloc::{
    string::{String, ToString},
    sync::Arc,
};
#[cfg(any(target_arch = "x86_64", target_arch = "loongarch64"))]
use alloc::format;
#[cfg(any(target_arch = "x86_64", target_arch = "loongarch64"))]
use core::sync::atomic::{AtomicUsize, Ordering};

use axfs::FS_CONTEXT;
use axhal::uspace::UserContext;
use axsync::Mutex;
use axtask::{AxTaskExt, spawn_task};
#[cfg(any(target_arch = "x86_64", target_arch = "loongarch64"))]
use axtask::{AxCpuMask, TaskInner, yield_now};
use starry_process::{Pid, Process};

use crate::{
    file::FD_TABLE,
    mm::{copy_from_kernel, load_user_app, new_user_aspace_empty},
    pseudofs::{self, dev::tty::N_TTY},
    task::{ProcessData, Thread, add_task_to_table, new_user_task, spawn_alarm_task},
};

#[cfg(any(target_arch = "x86_64", target_arch = "loongarch64"))]
fn init_vdso_getcpu_all_cpus() {
    static INITED_CPUS: AtomicUsize = AtomicUsize::new(0);

    let cpu_num = axhal::cpu_num();
    INITED_CPUS.store(0, Ordering::Release);

    for cpu_id in 0..cpu_num {
        let mut task = TaskInner::new(
            move || {
                starry_vdso::vdso::init_vdso_getcpu(cpu_id as u32, 0);
                INITED_CPUS.fetch_add(1, Ordering::AcqRel);
            },
            format!("vdso-getcpu-init-{cpu_id}"),
            axconfig::TASK_STACK_SIZE,
        );

        let mut cpumask = AxCpuMask::new();
        cpumask.set(cpu_id, true);
        task.set_cpumask(cpumask);
        spawn_task(task);
    }

    while INITED_CPUS.load(Ordering::Acquire) < cpu_num {
        yield_now();
    }

    info!("Initialized vDSO getcpu on {cpu_num} CPUs");
}

/// Initialize and run initproc.
pub fn init(args: &[String], envs: &[String]) {
    pseudofs::mount_all().expect("Failed to mount pseudofs");
    spawn_alarm_task();

    info!("Initialize vDSO data...");
    starry_vdso::vdso::init_vdso_data();
    #[cfg(any(target_arch = "x86_64", target_arch = "loongarch64"))]
    init_vdso_getcpu_all_cpus();

    axtask::register_timer_callback(|_| {
        starry_vdso::vdso::update_vdso_data();
    });

    let loc = FS_CONTEXT
        .lock()
        .resolve(&args[0])
        .expect("Failed to resolve executable path");
    let path = loc
        .absolute_path()
        .expect("Failed to get executable absolute path");
    let name = loc.name();

    let mut uspace = new_user_aspace_empty()
        .and_then(|mut it| {
            copy_from_kernel(&mut it)?;
            Ok(it)
        })
        .expect("Failed to create user address space");

    let (entry_vaddr, ustack_top) = load_user_app(&mut uspace, None, args, envs)
        .unwrap_or_else(|e| panic!("Failed to load user app: {}", e));

    let uctx = UserContext::new(entry_vaddr.into(), ustack_top, 0);
    let mut task = new_user_task(name, uctx, 0);
    task.ctx_mut().set_page_table_root(uspace.page_table_root());

    let pid = task.id().as_u64() as Pid;
    let proc = Process::new_init(pid);
    proc.add_thread(pid);

    N_TTY.bind_to(&proc).expect("Failed to bind ntty");

    let proc = ProcessData::new(
        proc,
        path.to_string(),
        Arc::new(args.to_vec()),
        Arc::new(Mutex::new(uspace)),
        Arc::default(),
        None,
    );

    {
        let mut scope = proc.scope.write();
        crate::file::add_stdio(&mut FD_TABLE.scope_mut(&mut scope).write())
            .expect("Failed to add stdio");
    }

    let thr = Thread::new(pid, proc);
    *task.task_ext_mut() = Some(AxTaskExt::from_impl(thr));

    let task = spawn_task(task);
    add_task_to_table(&task);

    // TODO: wait for all processes to finish
    let exit_code = task.join();
    info!("Init process exited with code: {exit_code:?}");

    let cx = FS_CONTEXT.lock();
    cx.root_dir()
        .unmount_all()
        .expect("Failed to unmount all filesystems");
    cx.root_dir()
        .filesystem()
        .flush()
        .expect("Failed to flush rootfs");
}
