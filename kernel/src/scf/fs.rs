use crate::{mm::{UserInPtr, UserOutPtr}, task::CurrentTask};


pub fn sys_read(fd: usize, mut buf: UserOutPtr<u8>, len: usize) -> isize {
    CurrentTask::get().scf_read(fd as _, buf.as_mut_ptr(), len)
}

pub fn sys_write(fd: usize, buf: UserInPtr<u8>, len: usize) -> isize {
    CurrentTask::get().scf_write(fd as _, buf.as_ptr(), len)
}