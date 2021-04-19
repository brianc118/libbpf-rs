use nix::{libc, unistd};
use std::io;

use crate::*;

/// Represents a bpf iterator for reading kernel data structures. This requires
/// Linux 5.8.
pub struct Iter {
    link: Link,
}

impl Iter {
    pub fn new(link: Link) -> Self {
        Self { link }
    }

    /// Open the iterator for reading.
    pub fn open(&self) -> Result<OpenIter> {
        let link_fd = self.link.get_fd();
        let fd = unsafe { libbpf_sys::bpf_iter_create(link_fd) };
        if fd < 0 {
            return Err(Error::System(-fd));
        }
        Ok(OpenIter { fd })
    }
}

/// Represents an open instance of a bpf iterator. This requires Linux 5.8.
///
/// This implements [`std::io::Read`] for reading bytes from the iterator.
/// Methods require working with raw bytes. You may find libraries such as
/// [`plain`](https://crates.io/crates/plain) helpful.
pub struct OpenIter {
    fd: i32,
}

impl OpenIter {
    pub fn new(fd: i32) -> Self {
        Self { fd }
    }
}

impl Drop for OpenIter {
    fn drop(&mut self) {
        let _ = unistd::close(self.fd);
    }
}

impl io::Read for OpenIter {
    fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        let bytes_read = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if bytes_read < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(bytes_read as usize)
    }
}
