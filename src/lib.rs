use bsd_kvm_sys::{kinfo_proc, kvm_t, priority, rusage, sigset_t, timeval, _SIG_WORDS};
use libc::{
    COMMLEN, KI_EMULNAMELEN, KI_NGROUPS, LOCKNAMELEN, LOGINCLASSLEN, LOGNAMELEN, MAXCOMLEN,
    O_RDONLY, O_RDWR, O_WRONLY, TDNAMLEN, WMESGLEN, _POSIX2_LINE_MAX,
};
use std::ffi::{CStr, CString};
use std::path::Path;
use thiserror::Error;

#[derive(Clone, Copy, Debug)]
pub enum Access {
    ReadOnly = O_RDONLY as isize,
    WriteOnly = O_WRONLY as isize,
    ReadWrite = O_RDWR as isize,
}

pub struct Kvm {
    ptr: *mut kvm_t,
}

#[derive(Error, Debug)]
pub enum KvmError {
    #[error("kvm open failed: {0}")]
    Open(String),
}

impl Kvm {
    pub fn open<T: AsRef<Path>>(
        execfile: Option<T>,
        corefile: Option<T>,
        flags: Access,
    ) -> Result<Kvm, KvmError> {
        let execfile =
            execfile.map(|x| CString::new(x.as_ref().to_string_lossy().into_owned()).unwrap());
        let execfile_ptr = if let Some(ref x) = execfile {
            x.as_ptr() as *const i8
        } else {
            std::ptr::null()
        };

        let corefile =
            corefile.map(|x| CString::new(x.as_ref().to_string_lossy().into_owned()).unwrap());
        let corefile_ptr = if let Some(ref x) = corefile {
            x.as_ptr() as *const i8
        } else {
            std::ptr::null()
        };

        let mut errbuf = [0i8; _POSIX2_LINE_MAX as usize];
        let kvm = unsafe {
            bsd_kvm_sys::kvm_openfiles(
                execfile_ptr,
                corefile_ptr,
                std::ptr::null(),
                flags as i32,
                errbuf.as_mut_ptr(),
            )
        };

        if kvm.is_null() {
            let ptr = errbuf.as_ptr() as *const u8;
            let len = errbuf.len();
            let err = unsafe { std::slice::from_raw_parts::<u8>(ptr, len) };
            if let Ok(err) = CStr::from_bytes_until_nul(err) {
                Err(KvmError::Open(err.to_string_lossy().into_owned()))
            } else {
                Err(KvmError::Open(String::from("")))
            }
        } else {
            Ok(Kvm { ptr: kvm })
        }
    }

    pub fn get_process(&mut self, op: KernProc, arg: i32) -> Vec<Process> {
        let mut num = 0;
        let procs = unsafe { bsd_kvm_sys::kvm_getprocs(self.ptr, op as i32, arg, &mut num) };

        let procs = unsafe { std::slice::from_raw_parts(procs, num as usize) };

        let mut ret = Vec::new();
        for proc in procs {
            let mut args_ptr = unsafe { bsd_kvm_sys::kvm_getargv(self.ptr, proc, 0) };

            let mut args = Vec::new();
            unsafe {
                if !args_ptr.is_null() {
                    while !(*args_ptr).is_null() {
                        let arg = CStr::from_ptr(*args_ptr);
                        args.push(arg.to_string_lossy().into_owned());
                        args_ptr = args_ptr.add(1);
                    }
                }
            }

            let mut envs_ptr = unsafe { bsd_kvm_sys::kvm_getenvv(self.ptr, proc, 0) };

            let mut envs = Vec::new();
            unsafe {
                if !envs_ptr.is_null() {
                    while !(*envs_ptr).is_null() {
                        let env = CStr::from_ptr(*envs_ptr);
                        envs.push(env.to_string_lossy().into_owned());
                        envs_ptr = envs_ptr.add(1);
                    }
                }
            }

            let p = Process {
                info: proc.into(),
                arg: args,
                env: envs,
            };
            ret.push(p);
        }
        ret
    }
}

impl Drop for Kvm {
    fn drop(&mut self) {
        let _ = unsafe { bsd_kvm_sys::kvm_close(self.ptr) };
    }
}

#[derive(Clone, Copy, Debug)]
pub enum KernProc {
    All = libc::KERN_PROC_ALL as isize,
    Proc = libc::KERN_PROC_PROC as isize,
    Pid = libc::KERN_PROC_PID as isize,
    Pgrp = libc::KERN_PROC_PGRP as isize,
    Session = libc::KERN_PROC_SESSION as isize,
    Tty = libc::KERN_PROC_TTY as isize,
    Uid = libc::KERN_PROC_UID as isize,
    Ruid = libc::KERN_PROC_RUID as isize,
    IncThread = libc::KERN_PROC_INC_THREAD as isize,
}

#[derive(Clone, Debug)]
pub struct Process {
    pub info: KinfoProc,
    pub arg: Vec<String>,
    pub env: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct KinfoProc {
    /// size of this structure
    pub structsize: i32,
    /// reserved: layout identifier
    pub layout: i32,
    /// address of command arguments
    pub args: *const i8,
    /// address of proc
    pub paddr: *const i8,
    /// kernel virtual addr of u-area
    pub addr: *const i8,
    /// pointer to trace file
    pub tracep: *const i8,
    /// pointer to executable file
    pub textvp: *const i8,
    /// pointer to open file info
    pub fd: *const i8,
    /// pointer to kernel vmspace struct
    pub vmspace: *const i8,
    /// sleep address
    pub wchan: *const i8,
    /// Process identifier
    pub pid: i32,
    /// parent process id
    pub ppid: i32,
    /// process group id
    pub pgid: i32,
    /// tty process group id
    pub tpgid: i32,
    /// Process session ID
    pub sid: i32,
    /// Terminal session ID
    pub tsid: i32,
    /// job control counter
    pub jobc: i32,
    /// controlling tty dev
    pub tdev_freebsd11: u32,
    /// Signals arrived but not delivered
    pub siglist: Sigset,
    /// Current signal mask
    pub sigmask: Sigset,
    /// Signals being ignored
    pub sigignore: Sigset,
    /// Signals being caught by user
    pub sigcatch: Sigset,
    /// effective user id
    pub uid: u32,
    /// Real user id
    pub ruid: u32,
    /// Saved effective user id
    pub svuid: u32,
    /// Real group id
    pub rgid: u32,
    /// Saved effective group id
    pub svgid: u32,
    /// number of groups
    pub ngroups: i16,
    /// groups
    pub groups: [u32; KI_NGROUPS as usize],
    /// virtual size
    pub size: u64,
    /// current resident set size in pages
    pub rssize: i64,
    /// resident set size before last swap
    pub swrss: i64,
    /// text size (pages) XXX
    pub tsize: i64,
    /// data size (pages) XXX
    pub dsize: i64,
    /// stack size (pages)
    pub ssize: i64,
    /// Exit status for wait & stop signal
    pub xstat: u16,
    /// Accounting flags
    pub acflag: u16,
    /// %cpu for process during ki_swtime
    pub pctcpu: u32,
    /// Time averaged value of ki_cpticks
    pub estcpu: u32,
    /// Time since last blocked
    pub slptime: u32,
    /// Time swapped in or out
    pub swtime: u32,
    /// number of copy-on-write faults
    pub cow: u32,
    /// Real time in microsec
    pub runtime: u64,
    /// starting time
    pub start: Timeval,
    /// time used by process children
    pub childtime: Timeval,
    /// P_* flags
    pub flag: i64,
    /// KI_* flags (below)
    pub kiflag: i64,
    /// Kernel trace points
    pub traceflag: i32,
    /// S* process status
    pub stat: i8,
    /// Process "nice" value
    pub nice: i8,
    /// Process lock (prevent swap) count
    pub lock: i8,
    /// Run queue index
    pub rqindex: i8,
    /// Which cpu we are on (legacy)
    pub oncpu_old: u8,
    /// Last cpu we were on (legacy)
    pub lastcpu_old: u8,
    /// thread name
    pub tdname: [i8; TDNAMLEN as usize + 1],
    /// wchan message
    pub wmesg: [i8; WMESGLEN as usize + 1],
    /// setlogin name
    pub login: [i8; LOGNAMELEN as usize + 1],
    /// lock name
    pub lockname: [i8; LOCKNAMELEN as usize + 1],
    /// command name
    pub comm: [i8; COMMLEN as usize + 1],
    /// emulation name
    pub emul: [i8; KI_EMULNAMELEN as usize + 1],
    /// login class
    pub loginclass: [i8; LOGINCLASSLEN as usize + 1],
    /// more thread name
    pub moretdname: [i8; MAXCOMLEN as usize - TDNAMLEN as usize + 1],
    /// controlling tty dev
    pub tdev: u64,
    /// Which cpu we are on
    pub oncpu: i32,
    /// Last cpu we were on
    pub lastcpu: i32,
    /// Pid of tracing process
    pub tracer: i32,
    /// P2_* flags
    pub flag2: i32,
    /// Default FIB number
    pub fibnum: i32,
    /// Credential flags
    pub cr_flags: u32,
    /// Process jail ID
    pub jid: i32,
    /// XXXKSE number of threads in total
    pub numthreads: i32,
    /// XXXKSE thread id
    pub tid: i32,
    /// process priority
    pub pri: Priority,
    /// process rusage statistics
    pub rusage: Rusage,
    /// rusage of children processes
    pub rusage_ch: Rusage,
    /// kernel virtual addr of pcb
    pub pcb: *const i8,
    /// kernel virtual addr of stack
    pub kstack: *const i8,
    /// User convenience pointer
    pub udata: *const i8,
    /// address of thread
    pub tdaddr: *const i8,
    /// PS_* flags
    pub sflag: i64,
    /// XXXKSE kthread flag
    pub tdflags: i64,
}

impl From<&kinfo_proc> for KinfoProc {
    fn from(x: &kinfo_proc) -> Self {
        Self {
            structsize: x.ki_structsize,
            layout: x.ki_layout,
            args: x.ki_args as *const i8,
            paddr: x.ki_paddr as *const i8,
            addr: x.ki_addr as *const i8,
            tracep: x.ki_tracep as *const i8,
            textvp: x.ki_textvp as *const i8,
            fd: x.ki_fd as *const i8,
            vmspace: x.ki_vmspace as *const i8,
            wchan: x.ki_wchan as *const i8,
            pid: x.ki_pid,
            ppid: x.ki_ppid,
            pgid: x.ki_pgid,
            tpgid: x.ki_tpgid,
            sid: x.ki_sid,
            tsid: x.ki_tsid,
            jobc: x.ki_tsid,
            tdev_freebsd11: x.ki_tdev_freebsd11,
            siglist: x.ki_siglist.into(),
            sigmask: x.ki_sigmask.into(),
            sigignore: x.ki_sigignore.into(),
            sigcatch: x.ki_sigcatch.into(),
            uid: x.ki_uid,
            ruid: x.ki_ruid,
            svuid: x.ki_svuid,
            rgid: x.ki_rgid,
            svgid: x.ki_svgid,
            ngroups: x.ki_ngroups,
            groups: x.ki_groups,
            size: x.ki_size,
            rssize: x.ki_rssize,
            swrss: x.ki_swrss,
            tsize: x.ki_tsize,
            dsize: x.ki_dsize,
            ssize: x.ki_ssize,
            xstat: x.ki_xstat,
            acflag: x.ki_acflag,
            pctcpu: x.ki_pctcpu,
            estcpu: x.ki_estcpu,
            slptime: x.ki_slptime,
            swtime: x.ki_swtime,
            cow: x.ki_cow,
            runtime: x.ki_runtime,
            start: x.ki_start.into(),
            childtime: x.ki_childtime.into(),
            flag: x.ki_flag,
            kiflag: x.ki_kiflag,
            traceflag: x.ki_traceflag,
            stat: x.ki_stat,
            nice: x.ki_nice,
            lock: x.ki_lock,
            rqindex: x.ki_rqindex,
            oncpu_old: x.ki_oncpu_old,
            lastcpu_old: x.ki_lastcpu_old,
            tdname: x.ki_tdname,
            wmesg: x.ki_wmesg,
            login: x.ki_login,
            lockname: x.ki_lockname,
            comm: x.ki_comm,
            emul: x.ki_emul,
            loginclass: x.ki_loginclass,
            moretdname: x.ki_moretdname,
            tdev: x.ki_tdev,
            oncpu: x.ki_oncpu,
            lastcpu: x.ki_lastcpu,
            tracer: x.ki_tracer,
            flag2: x.ki_flag2,
            fibnum: x.ki_fibnum,
            cr_flags: x.ki_cr_flags,
            jid: x.ki_jid,
            numthreads: x.ki_numthreads,
            tid: x.ki_tid,
            pri: x.ki_pri.into(),
            rusage: x.ki_rusage.into(),
            rusage_ch: x.ki_rusage_ch.into(),
            pcb: x.ki_pcb as *const i8,
            kstack: x.ki_kstack as *const i8,
            udata: x.ki_udata as *const i8,
            tdaddr: x.ki_tdaddr as *const i8,
            sflag: x.ki_sflag,
            tdflags: x.ki_tdflags,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Sigset(pub [u32; _SIG_WORDS as usize]);

impl From<sigset_t> for Sigset {
    fn from(x: sigset_t) -> Self {
        Sigset([x.__bits[0], x.__bits[1], x.__bits[2], x.__bits[3]])
    }
}

#[derive(Clone, Debug)]
pub struct Timeval {
    /// seconds
    pub sec: i64,
    /// and microseconds
    pub usec: i64,
}

impl Timeval {
    pub fn to_us(&self) -> i64 {
        self.sec * 1_000_000 + self.usec
    }
}

impl From<timeval> for Timeval {
    fn from(x: timeval) -> Self {
        Timeval {
            sec: x.tv_sec,
            usec: x.tv_usec,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Priority {
    /// Scheduling class.
    pub class: u8,
    /// Normal priority level.
    pub level: u8,
    /// Priority before propagation.
    pub native: u8,
    /// User priority based on p_cpu and p_nice.
    pub user: u8,
}

impl From<priority> for Priority {
    fn from(x: priority) -> Self {
        Priority {
            class: x.pri_class,
            level: x.pri_level,
            native: x.pri_native,
            user: x.pri_user,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Rusage {
    /// user time used
    pub utime: Timeval,
    /// system time used
    pub stime: Timeval,
    /// max resident set size
    pub maxrss: i64,
    /// integral shared memory size
    pub ixrss: i64,
    /// integral unshared data "
    pub idrss: i64,
    /// integral unshared stack "
    pub isrss: i64,
    /// page reclaims
    pub minflt: i64,
    /// page faults
    pub majflt: i64,
    /// swaps
    pub nswap: i64,
    /// block input operations
    pub inblock: i64,
    /// block output operations
    pub oublock: i64,
    /// messages sent
    pub msgsnd: i64,
    /// messages received
    pub msgrcv: i64,
    /// signals received
    pub nsignals: i64,
    /// voluntary context switches
    pub nvcsw: i64,
    /// involuntary "
    pub nivcsw: i64,
}

impl From<rusage> for Rusage {
    fn from(x: rusage) -> Self {
        Rusage {
            utime: x.ru_utime.into(),
            stime: x.ru_stime.into(),
            maxrss: x.ru_maxrss,
            ixrss: x.ru_ixrss,
            idrss: x.ru_idrss,
            isrss: x.ru_isrss,
            minflt: x.ru_minflt,
            majflt: x.ru_majflt,
            nswap: x.ru_nswap,
            inblock: x.ru_inblock,
            oublock: x.ru_oublock,
            msgsnd: x.ru_msgsnd,
            msgrcv: x.ru_msgrcv,
            nsignals: x.ru_nsignals,
            nvcsw: x.ru_nvcsw,
            nivcsw: x.ru_nivcsw,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_process() {
        let mut kvm = Kvm::open(None, Some("/dev/null"), Access::ReadOnly).unwrap();
        let process = kvm.get_process(KernProc::Proc, 0);
        assert_ne!(process.len(), 0);
    }
}
