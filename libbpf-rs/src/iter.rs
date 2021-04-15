use nix::unistd::close;
use nix::{errno, libc};
use std::mem::{size_of, MaybeUninit};

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

    /// Read raw iterator as objects of type `T`.
    ///
    /// The data is read in chunks to an intermediate buffer of `BUF_SIZE`
    /// elements of type `T`.
    ///
    /// # Safety
    ///
    /// The type layout of `T` must match the layout of the data structure being
    /// dumped by the bpf program to guarantee that the returned objects are
    /// valid.
    pub unsafe fn read<T: Copy, const BUF_SIZE: usize>(&self) -> Result<Vec<T>> {
        let link_fd = self.link.get_fd();
        let fd = libbpf_sys::bpf_iter_create(link_fd);
        if fd < 0 {
            return Err(Error::System(-fd));
        }

        let mut buf: [MaybeUninit<T>; BUF_SIZE] = MaybeUninit::uninit().assume_init();
        let mut ret = Vec::new();

        loop {
            let bytes_read = libc::read(fd, buf.as_mut_ptr() as *mut _, BUF_SIZE * size_of::<T>());
            if bytes_read < 0 {
                let errno = errno::errno();
                let _ = close(fd);
                return Err(Error::System(errno));
            } else if bytes_read == 0 {
                break;
            } else if bytes_read as usize % size_of::<T>() != 0 {
                let _ = close(fd);
                return Err(Error::Internal(format!(
                    "Read {} bytes which is not a multiple of {}.",
                    bytes_read,
                    size_of::<T>()
                )));
            }
            let count = bytes_read as usize / size_of::<T>();
            for item in buf[0..count].iter() {
                ret.push(item.assume_init());
            }
        }
        let _ = close(fd);
        Ok(ret)
    }
}
