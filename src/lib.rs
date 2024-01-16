use bsd_kvm_sys::{kinfo_proc, kvm_t, priority, rusage, sigset_t, timeval, _SIG_WORDS};
use libc::{
    COMMLEN, KI_EMULNAMELEN, KI_NGROUPS, LOCKNAMELEN, LOGINCLASSLEN, LOGNAMELEN, MAXCOMLEN,
    O_RDONLY, O_RDWR, O_WRONLY, TDNAMLEN, WMESGLEN, _POSIX2_LINE_MAX,
};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
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
            x.as_ptr() as *const c_char
        } else {
            std::ptr::null()
        };

        let corefile =
            corefile.map(|x| CString::new(x.as_ref().to_string_lossy().into_owned()).unwrap());
        let corefile_ptr = if let Some(ref x) = corefile {
            x.as_ptr() as *const c_char
        } else {
            std::ptr::null()
        };

        let mut errbuf = [0 as c_char; _POSIX2_LINE_MAX as usize];
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
    pub args: *const c_char,
    /// address of proc
    pub paddr: *const c_char,
    /// kernel virtual addr of u-area
    pub addr: *const c_char,
    /// pointer to trace file
    pub tracep: *const c_char,
    /// pointer to executable file
    pub textvp: *const c_char,
    /// pointer to open file info
    pub fd: *const c_char,
    /// pointer to kernel vmspace struct
    pub vmspace: *const c_char,
    /// sleep address
    pub wchan: *const c_char,
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
    pub stat: c_char,
    /// Process "nice" value
    pub nice: i8,
    /// Process lock (prevent swap) count
    pub lock: c_char,
    /// Run queue index
    pub rqindex: c_char,
    /// Which cpu we are on (legacy)
    pub oncpu_old: u8,
    /// Last cpu we were on (legacy)
    pub lastcpu_old: u8,
    /// thread name
    pub tdname: [c_char; TDNAMLEN as usize + 1],
    /// wchan message
    pub wmesg: [c_char; WMESGLEN as usize + 1],
    /// setlogin name
    pub login: [c_char; LOGNAMELEN as usize + 1],
    /// lock name
    pub lockname: [c_char; LOCKNAMELEN as usize + 1],
    /// command name
    pub comm: [c_char; COMMLEN as usize + 1],
    /// emulation name
    pub emul: [c_char; KI_EMULNAMELEN as usize + 1],
    /// login class
    pub loginclass: [c_char; LOGINCLASSLEN as usize + 1],
    /// more thread name
    pub moretdname: [c_char; MAXCOMLEN as usize - TDNAMLEN as usize + 1],
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
    pub pcb: *const c_char,
    /// kernel virtual addr of stack
    pub kstack: *const c_char,
    /// User convenience pointer
    pub udata: *const c_char,
    /// address of thread
    pub tdaddr: *const c_char,
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
            args: x.ki_args as *const c_char,
            paddr: x.ki_paddr as *const c_char,
            addr: x.ki_addr as *const c_char,
            tracep: x.ki_tracep as *const c_char,
            textvp: x.ki_textvp as *const c_char,
            fd: x.ki_fd as *const c_char,
            vmspace: x.ki_vmspace as *const c_char,
            wchan: x.ki_wchan as *const c_char,
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
            size: x.ki_size as u64,
            rssize: x.ki_rssize as i64,
            swrss: x.ki_swrss as i64,
            tsize: x.ki_tsize as i64,
            dsize: x.ki_dsize as i64,
            ssize: x.ki_ssize as i64,
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
            flag: x.ki_flag as i64,
            kiflag: x.ki_kiflag as i64,
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
            pcb: x.ki_pcb as *const c_char,
            kstack: x.ki_kstack as *const c_char,
            udata: x.ki_udata as *const c_char,
            tdaddr: x.ki_tdaddr as *const c_char,
            sflag: x.ki_sflagas as i64,
            tdflags: x.ki_tdflags as i64,
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
            usec: x.tv_usec as i64,
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
            maxrss: x.ru_maxrss as i64,
            ixrss: x.ru_ixrss as i64,
            idrss: x.ru_idrss as i64,
            isrss: x.ru_isrss as i64,
            minflt: x.ru_minflt as i64,
            majflt: x.ru_majflt as i64,
            nswap: x.ru_nswap as i64,
            inblock: x.ru_inblock as i64,
            oublock: x.ru_oublock as i64,
            msgsnd: x.ru_msgsnd as i64,
            msgrcv: x.ru_msgrcv as i64,
            nsignals: x.ru_nsignals as i64,
            nvcsw: x.ru_nvcsw as i64,
            nivcsw: x.ru_nivcsw as i64,
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
