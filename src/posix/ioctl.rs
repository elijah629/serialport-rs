#[cfg(any(
    target_os = "android",
    all(
        target_os = "linux",
        not(any(
            target_env = "musl",
            target_arch = "powerpc",
            target_arch = "powerpc64"
        ))
    )
))]
use std::os::{fd::AsRawFd, unix::io::RawFd};

use bitflags::bitflags;
use nix::libc;

use crate::Result;

// These are wrapped in a module because they're `pub` by default
mod raw {
    use nix::libc;
    use nix::{ioctl_none_bad, ioctl_read, ioctl_read_bad, ioctl_write_ptr, ioctl_write_ptr_bad};

    ioctl_none_bad!(tiocexcl, libc::TIOCEXCL);
    ioctl_none_bad!(tiocnxcl, libc::TIOCNXCL);
    ioctl_read_bad!(tiocmget, libc::TIOCMGET, libc::c_int);
    ioctl_none_bad!(tiocsbrk, libc::TIOCSBRK);
    ioctl_none_bad!(tioccbrk, libc::TIOCCBRK);

    #[cfg(any(target_os = "android", target_os = "linux"))]
    ioctl_read_bad!(fionread, libc::FIONREAD, libc::c_int);

    // See: /usr/include/sys/filio.h
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    ioctl_read!(fionread, b'f', 127, libc::c_int);

    #[cfg(any(target_os = "android", target_os = "linux"))]
    ioctl_read_bad!(tiocoutq, libc::TIOCOUTQ, libc::c_int);

    // See: /usr/include/sys/ttycom.h
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    ioctl_read!(tiocoutq, b't', 115, libc::c_int);

    ioctl_write_ptr_bad!(tiocmbic, libc::TIOCMBIC, libc::c_int);
    ioctl_write_ptr_bad!(tiocmbis, libc::TIOCMBIS, libc::c_int);
    ioctl_read!(
        #[cfg(any(
            target_os = "android",
            all(
                target_os = "linux",
                not(any(
                    target_env = "musl",
                    target_arch = "powerpc",
                    target_arch = "powerpc64"
                ))
            )
        ))]
        tcgets2,
        b'T',
        0x2A,
        libc::termios2
    );
    ioctl_write_ptr!(
        #[cfg(any(
            target_os = "android",
            all(
                target_os = "linux",
                not(any(
                    target_env = "musl",
                    target_arch = "powerpc",
                    target_arch = "powerpc64"
                ))
            )
        ))]
        tcsets2,
        b'T',
        0x2B,
        libc::termios2
    );
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    const IOSSIOSPEED: libc::c_ulong = 0x80045402;
    ioctl_write_ptr_bad!(
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        iossiospeed,
        IOSSIOSPEED,
        libc::speed_t
    );
}

bitflags! {
    /// Flags to indicate which wires in a serial connection to use
    pub struct SerialLines: libc::c_int {
        const DATA_SET_READY = libc::TIOCM_DSR;
        const DATA_TERMINAL_READY = libc::TIOCM_DTR;
        const REQUEST_TO_SEND = libc::TIOCM_RTS;
        const SECONDARY_TRANSMIT = libc::TIOCM_ST;
        const SECONDARY_RECEIVE = libc::TIOCM_SR;
        const CLEAR_TO_SEND = libc::TIOCM_CTS;
        const DATA_CARRIER_DETECT = libc::TIOCM_CAR;
        const RING = libc::TIOCM_RNG;
    }
}

pub fn tiocexcl<F: AsRawFd>(fd: F) -> Result<()> {
    unsafe { raw::tiocexcl(fd.as_raw_fd()) }
        .map(|_| ())
        .map_err(|e| e.into())
}

pub fn tiocnxcl<F: AsRawFd>(fd: F) -> Result<()> {
    unsafe { raw::tiocnxcl(fd.as_raw_fd()) }
        .map(|_| ())
        .map_err(|e| e.into())
}

pub fn tiocmget<F: AsRawFd>(fd: F) -> Result<SerialLines> {
    let mut status: libc::c_int = 0;
    unsafe { raw::tiocmget(fd.as_raw_fd(), &mut status) }
        .map(|_| SerialLines::from_bits_truncate(status))
        .map_err(|e| e.into())
}

pub fn tiocsbrk(fd: RawFd) -> Result<()> {
    unsafe { raw::tiocsbrk(fd) }
        .map(|_| ())
        .map_err(|e| e.into())
}

pub fn tioccbrk(fd: RawFd) -> Result<()> {
    unsafe { raw::tioccbrk(fd) }
        .map(|_| ())
        .map_err(|e| e.into())
}

pub fn fionread(fd: RawFd) -> Result<u32> {
    let mut retval: libc::c_int = 0;
    unsafe { raw::fionread(fd, &mut retval) }
        .map(|_| retval as u32)
        .map_err(|e| e.into())
}

pub fn tiocoutq(fd: RawFd) -> Result<u32> {
    let mut retval: libc::c_int = 0;
    unsafe { raw::tiocoutq(fd, &mut retval) }
        .map(|_| retval as u32)
        .map_err(|e| e.into())
}

pub fn tiocmbic<F: AsRawFd>(fd: F, status: SerialLines) -> Result<()> {
    let bits = status.bits() as libc::c_int;
    unsafe { raw::tiocmbic(fd.as_raw_fd(), &bits) }
        .map(|_| ())
        .map_err(|e| e.into())
}

pub fn tiocmbis<F: AsRawFd>(fd: F, status: SerialLines) -> Result<()> {
    let bits = status.bits() as libc::c_int;
    unsafe { raw::tiocmbis(fd.as_raw_fd(), &bits) }
        .map(|_| ())
        .map_err(|e| e.into())
}

#[cfg(any(
    target_os = "android",
    all(
        target_os = "linux",
        not(any(
            target_env = "musl",
            target_arch = "powerpc",
            target_arch = "powerpc64"
        ))
    )
))]
pub fn tcgets2<F: AsRawFd>(fd: F) -> Result<libc::termios2> {
    let mut options = std::mem::MaybeUninit::uninit();
    match unsafe { raw::tcgets2(fd.as_raw_fd(), options.as_mut_ptr()) } {
        Ok(_) => unsafe { Ok(options.assume_init()) },
        Err(e) => Err(e.into()),
    }
}

#[cfg(any(
    target_os = "android",
    all(
        target_os = "linux",
        not(any(
            target_env = "musl",
            target_arch = "powerpc",
            target_arch = "powerpc64"
        ))
    )
))]
pub fn tcsets2<F: AsRawFd>(fd: F, options: &libc::termios2) -> Result<()> {
    unsafe { raw::tcsets2(fd.as_raw_fd(), options) }
        .map(|_| ())
        .map_err(|e| e.into())
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub fn iossiospeed(fd: RawFd, baud_rate: &libc::speed_t) -> Result<()> {
    unsafe { raw::iossiospeed(fd, baud_rate) }
        .map(|_| ())
        .map_err(|e| e.into())
}
