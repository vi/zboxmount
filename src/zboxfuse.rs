#![allow(unused)]
use fuse_mt::{FileAttr, FilesystemMT, RequestInfo, ResultEmpty, ResultEntry};
use libc::c_int;
use log::{debug, error, warn};
use std::ffi::OsStr;
use std::path::Path;
use time::Timespec;
use zbox::{Repo};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct ZboxFs(Repo);

fn ze2errno(e: zbox::Error) -> c_int {
    use libc::{
        EACCES, EADDRINUSE, EADDRNOTAVAIL, ECONNABORTED, ECONNREFUSED, ECONNRESET, EEXIST, EINVAL,
        EIO, EISDIR, ENOENT, ENOMSG, ENOTCONN, ENOTDIR, ENOTEMPTY, EPERM, EPIPE, ETIMEDOUT,
    };
    use std::io::ErrorKind;
    use zbox::Error::{
        AlreadyExists, CannotRead, CannotWrite, Closed, Corrupted, Decrypt, Encrypt, Hashing,
        InTrans, InUse, InitCrypto, InvalidArgument, InvalidCipher, InvalidCost, InvalidPath,
        InvalidSuperBlk, InvalidUri, IsDir, IsFile, IsRoot, NoAesHardware, NoContent, NoEntity,
        NoTrans, NoVersion, NotDir, NotEmpty, NotFile, NotFinish, NotFound, NotInSync, NotInTrans,
        NotWrite, ReadOnly, RefOverflow, RefUnderflow, RepoClosed, RepoExists, RepoOpened,
        Uncompleted, WrongVersion, Io, Var, Encode, Decode
    };
    match e {
        Io(e) => match e.kind() {
            ErrorKind::AddrInUse => EADDRINUSE,
            ErrorKind::AddrNotAvailable => EADDRNOTAVAIL,
            ErrorKind::AlreadyExists => EEXIST,
            ErrorKind::BrokenPipe => EPIPE,
            ErrorKind::ConnectionAborted => ECONNABORTED,
            ErrorKind::ConnectionRefused => ECONNREFUSED,
            ErrorKind::ConnectionReset => ECONNRESET,
            ErrorKind::Interrupted => {
                error!("Suddenly got Interrupted IO error kind");
                ENOMSG
            }
            ErrorKind::InvalidData => EINVAL,
            ErrorKind::InvalidInput => EINVAL,
            ErrorKind::NotConnected => ENOTCONN,
            ErrorKind::NotFound => ENOENT,
            ErrorKind::PermissionDenied => EPERM,
            ErrorKind::TimedOut => ETIMEDOUT,
            ErrorKind::UnexpectedEof => EIO,
            ErrorKind::WouldBlock => {
                error!("Suddenly got WouldBlock IO error kind");
                ENOMSG
            }
            ErrorKind::WriteZero => {
                error!("Suddenly got WriteZero IO error kind");
                EIO
            }
            _ => {
                error!("Suddenly got unknown IO error: {}", e);
                ENOMSG
            }
        },
        Encode(ei) => {
            error!("Encode error: {}", ei);
            EIO
        }
        Decode(ei) => {
            error!("Decode error: {}", ei);
            EIO
        }
        Var(ei) => {
            error!("Environment variable error: {}", ei);
            EIO
        }
        RefOverflow | RefUnderflow | InitCrypto | NoAesHardware | Hashing | InvalidCost
        | InvalidCipher | InvalidUri | InvalidSuperBlk | RepoOpened | RepoClosed | RepoExists => {
            error!("Strange error from zbox: {}", e);
            ENOMSG
        }

        Encrypt | Decrypt | Corrupted | WrongVersion | NoEntity | NotInSync | InTrans
        | NotInTrans | NoTrans | Uncompleted | InUse | InvalidArgument | NoVersion | NotWrite
        | NotFinish | Closed => {
            error!("Strange error from zbox: {}", e);
            EIO
        }

        NoContent | InvalidPath | NotFound => ENOENT,

        AlreadyExists => EEXIST,

        IsRoot | IsDir | NotFile => EISDIR,

        IsFile | NotDir => ENOTDIR,

        NotEmpty => ENOTEMPTY,

        ReadOnly | CannotWrite | CannotRead => EACCES,
        e => {
            error!("Unknown error: {}", e);
            ENOMSG
        }
    }
}

fn systime2timespec(t : std::time::SystemTime) -> Timespec {
    if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
        Timespec {
            sec: d.as_secs() as i64,
            nsec: d.subsec_nanos() as i32,
        }
    } else {
        Timespec { sec: 0, nsec: 0 }
    }
}

fn zmeta2fa(m : zbox::Metadata) -> fuse_mt::FileAttr {
    fuse_mt::FileAttr  {
        size: 0,
        blocks: 0,
        atime: Timespec{sec: 0, nsec: 0},
        mtime: systime2timespec(m.modified_at()),
        ctime: Timespec{sec: 0, nsec: 0},
        crtime: systime2timespec(m.created_at()),
        kind: match m.file_type() {
            zbox::FileType::File => fuse_mt::FileType::RegularFile,
            zbox::FileType::Dir => fuse_mt::FileType::Directory,
        },
        perm: match m.file_type() {
            zbox::FileType::File => 0o666,
            zbox::FileType::Dir => 0o777,
        },
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        flags: 0,
    }
}

const TTL: Timespec = Timespec { sec: 1, nsec: 0 };

impl FilesystemMT for ZboxFs {
    fn init(&self, _req: RequestInfo) -> ResultEmpty {
        Ok(())
    }
    fn getattr(&self, _req: RequestInfo, path: &Path, _fh: Option<u64>) -> ResultEntry {
        match self.0.metadata(path) {
            Ok(m) => {
                Ok((TTL, zmeta2fa(m)))
            }
            Err(e) => Err(ze2errno(e)),
        }
    }
}

pub fn mount<'q>(
    repo: Repo,
    path: impl AsRef<Path>,
    fuse_opts: impl AsRef<[&'q OsStr]>,
    threads: usize,
) -> Result<()> {
    let zboxfs = ZboxFs(repo);
    let mt = fuse_mt::FuseMT::new(zboxfs, threads);
    fuse_mt::mount(mt, &path, fuse_opts.as_ref())?;
    Ok(())
}
