use anyhow::{bail, Result};
use libbpf_rs::Iter;

mod bpf;
use bpf::*;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TaskStatData {
    pub pid: i32,
    pub tid: i32,
    pub uid: u64,
    pub utime: u64,
    pub stime: u64,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn main() -> Result<()> {
    bump_memlock_rlimit()?;

    let mut skel_builder = TaskiterSkelBuilder::default();
    skel_builder.obj_builder.debug(false);
    let mut skel = skel_builder.open()?.load()?;
    skel.attach()?;
    let iter = Iter::new(skel.links.dump_taskstat_data.unwrap());

    const BUF_SIZE: usize = 4096;
    let mut tasks = unsafe { iter.read::<TaskStatData, BUF_SIZE>()? };

    tasks.sort_by_key(|k| k.pid);
    tasks.dedup_by_key(|k| k.pid);

    println!("{0: >10} {1: <10}", "pid", "uid");
    for task in tasks.iter() {
        println!("{0: >10} {1: <10}", task.pid, task.uid);
    }

    Ok(())
}
