use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::queue::ScfRequestToken;
use super::SCF;
use crate::mm::{UserInPtr, UserOutPtr};
use crate::task::CurrentTask;

numeric_enum_macro::numeric_enum! {
    #[repr(u8)]
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub enum ScfOpcode {
        Nop = 0,
        Read = 1,
        Write = 2,
        Open = 3,
        Close = 4,
        SyncMap = 5,
        SyncUnmap = 6,
        SyncFork = 7,
        Unknown = 0xff,
    }
}

const CHUNK_SIZE: usize = 256;

pub struct SyscallCondVar {
    ok: AtomicBool,
    ret_val: AtomicU64,
}

impl SyscallCondVar {
    pub fn new() -> Self {
        Self {
            ok: AtomicBool::new(false),
            ret_val: AtomicU64::new(0),
        }
    }

    pub fn signal(&self, ret_val: u64) {
        self.ret_val.store(ret_val, Ordering::Release);
        self.ok.store(true, Ordering::Release);
    }

    pub fn wait(&self) -> u64 {
        while !self.ok.load(Ordering::Acquire) {
            CurrentTask::get().yield_now();
        }
        self.ret_val.load(Ordering::Acquire)
    }
}

impl SCF {
    fn send_request(&mut self, opcode: ScfOpcode, args: [u64; 4], token: ScfRequestToken, irq_num: usize) {
        while !self.queue().send(opcode, args, token) {
            CurrentTask::get().yield_now();
        }
        super::notify(irq_num);
    }

    fn send_request_kernel(&mut self, opcode: ScfOpcode, args: [u64; 4], token: ScfRequestToken, irq_num: usize) {
        while !self.queue().send(opcode, args, token) {
            core::hint::spin_loop();
        }
        super::notify(irq_num);
    }

    pub fn write(&mut self, fd: usize, buf: UserInPtr<u8>, len: usize) -> isize {
        debug!("sys_write: fd={}, buf={:#x}, len={}, slot={}", fd, buf.as_ptr() as usize, len, self.slot_num);
        assert!(len < CHUNK_SIZE);
        let cond = SyscallCondVar::new();
        self.send_request(
            ScfOpcode::Write,
            [fd as _, buf.as_ptr() as _, len as _, 0],
            ScfRequestToken::from(&cond),
            self.irq_num(),
        );
        let ret = cond.wait();
        ret as _
    }

    pub fn read(&mut self, fd: usize, mut buf: UserOutPtr<u8>, len: usize) -> isize {
        debug!("sys_read: fd={}, buf={:#x}, len={}, slot={}", fd, buf.as_ptr() as usize, len, self.slot_num);
        assert!(len < CHUNK_SIZE);
        let cond = SyscallCondVar::new();
        self.send_request(
            ScfOpcode::Read,
            [fd as _, buf.as_mut_ptr() as _, len as _, 0],
            ScfRequestToken::from(&cond),
            self.irq_num(),
        );
        let ret = cond.wait();
        ret as _
    }

    pub fn syncmap(&mut self, vaddr: usize, len: usize, paddr: usize, prot: usize) -> isize {
        debug!("sys_syncmap: vaddr={:#x}, len={:#x}, paddr={:#x}, prot={:#x}, slot={}", vaddr, len, paddr, prot, self.slot_num);
        let cond = SyscallCondVar::new();
        self.send_request_kernel(
            ScfOpcode::SyncMap,
            [vaddr as _, len as _, paddr as _, prot as _],
            ScfRequestToken::from(&cond),
            self.irq_num()
        );

        // Better waiting strategy?
        loop {
            let response = self.queue().pop_response();
            if response.is_some() {
                let scf_response = response.unwrap();
                let ret = scf_response.ret_val;
                debug!("sys_syncmap: response received: ret={:#x}", ret);
                return ret as _;
            }
        }
    }

    pub fn syncunmap(&mut self, vaddr: usize, len: usize) -> isize {
        debug!("sys_syncunmap: vaddr={:#x}, len={:#x}, slot={}", vaddr, len, self.slot_num);
        let cond = SyscallCondVar::new();
        self.send_request_kernel(
            ScfOpcode::SyncUnmap,
            [vaddr as _, len as _, 0, 0],
            ScfRequestToken::from(&cond),
            self.irq_num()
        );

        // Better waiting strategy?
        loop {
            let response = self.queue().pop_response();
            if response.is_some() {
                let scf_response = response.unwrap();
                let ret = scf_response.ret_val;
                debug!("sys_syncunmap: response received: ret={:#x}", ret);
                return ret as _;
            }
        }
    }

    pub fn syncfork(&mut self) -> isize {
        debug!("sys_syncfork: slot={}", self.slot_num);
        let cond = SyscallCondVar::new();
        self.send_request(
            ScfOpcode::SyncFork,
            [0; 4],
            ScfRequestToken::from(&cond),
            self.irq_num()
        );

        // Better waiting strategy?
        loop {
            let response = self.queue().pop_response();
            if response.is_some() {
                let scf_response = response.unwrap();
                let ret = scf_response.ret_val;
                debug!("sys_syncfork: response received: ret={}", ret);
                return ret as _;
            }
        }
    }
}
