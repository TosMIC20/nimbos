//! Syscall Forwarding.

mod allocator;
mod queue;

pub mod syscall;

use self::syscall::ScfOpcode;
use crate::config::scf;
pub use syscall::sys_syncmap;

pub fn notify() {
    crate::drivers::interrupt::send_ipi(scf::SYSCALL_IPI_IRQ_NUM);
}

pub fn init() {
    queue::init();
    allocator::init();
}
