#![allow(unused)]
use fuse_mt::{
    CreatedEntry, FileAttr, FilesystemMT, RequestInfo, ResultCreate, ResultData, ResultEmpty,
    ResultEntry, ResultOpen, ResultReaddir, ResultWrite, ResultXattr
};
use libc::c_int;
use log::{debug, error, warn};
use std::ffi::OsStr;
use std::path::Path;
use std::sync::Mutex;
use time::Timespec;
use zbox::{File, OpenOptions, Repo};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn ie2errno(e: std::io::Error) -> c_int {
    use libc::{
        EACCES, EADDRINUSE, EADDRNOTAVAIL, ECONNABORTED, ECONNREFUSED, ECONNRESET, EEXIST, EINVAL,
        EIO, EISDIR, ENOENT, ENOMSG, ENOTCONN, ENOTDIR, ENOTEMPTY, EPERM, EPIPE, ETIMEDOUT,
    };
    use std::io::ErrorKind;
    match e.kind() {
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
    }
}

fn ze2errno(e: zbox::Error) -> c_int {
    use libc::{
        EACCES, EADDRINUSE, EADDRNOTAVAIL, ECONNABORTED, ECONNREFUSED, ECONNRESET, EEXIST, EINVAL,
        EIO, EISDIR, ENOENT, ENOMSG, ENOTCONN, ENOTDIR, ENOTEMPTY, EPERM, EPIPE, ETIMEDOUT,
    };
    use std::io::ErrorKind;
    use zbox::Error::{
        AlreadyExists, CannotRead, CannotWrite, Closed, Corrupted, Decode, Decrypt, Encode,
        Encrypt, Hashing, InTrans, InUse, InitCrypto, InvalidArgument, InvalidCipher, InvalidCost,
        InvalidPath, InvalidSuperBlk, InvalidUri, Io, IsDir, IsFile, IsRoot, NoAesHardware,
        NoContent, NoEntity, NoTrans, NoVersion, NotDir, NotEmpty, NotFile, NotFinish, NotFound,
        NotInSync, NotInTrans, NotWrite, ReadOnly, RefOverflow, RefUnderflow, RepoClosed,
        RepoExists, RepoOpened, Uncompleted, Var, WrongVersion,
    };
    match e {
        Io(e) => ie2errno(e),
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

fn systime2timespec(t: std::time::SystemTime) -> Timespec {
    if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
        Timespec {
            sec: d.as_secs() as i64,
            nsec: d.subsec_nanos() as i32,
        }
    } else {
        Timespec { sec: 0, nsec: 0 }
    }
}

fn zft2fft(ft : zbox::FileType) -> fuse_mt::FileType {
    match ft {
        zbox::FileType::File => fuse_mt::FileType::RegularFile,
        zbox::FileType::Dir => fuse_mt::FileType::Directory,
    }
}

fn zmeta2fa(m: zbox::Metadata) -> fuse_mt::FileAttr {
    fuse_mt::FileAttr {
        size: m.content_len() as u64,
        blocks: ((m.content_len()+8191) / 8192) as u64,
        atime: Timespec { sec: 0, nsec: 0 },
        mtime: systime2timespec(m.modified_at()),
        ctime: Timespec { sec: 0, nsec: 0 },
        crtime: systime2timespec(m.created_at()),
        kind: zft2fft(m.file_type()),
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

fn flags2openoptions(fl: libc::c_int) -> zbox::OpenOptions {
    let mut oo = OpenOptions::new();
    match fl & libc::O_ACCMODE {
        libc::O_RDONLY => {
            oo.read(true);
            oo.write(false);
        }
        libc::O_WRONLY => {
            oo.read(false);
            oo.write(true);
        }
        libc::O_RDWR => {
            oo.read(true);
            oo.write(true);
        }
        _ => {
            oo.read(false);
            oo.write(false);
        }
    }
    if fl & libc::O_CREAT != 0 {
        oo.create(true);
    }
    if fl & libc::O_EXCL != 0 {
        oo.create_new(true);
    }
    if fl & libc::O_APPEND != 0 {
        oo.append(true);
    }
    if fl & libc::O_TRUNC != 0 {
        oo.truncate(true);
    }
    oo
}

const TTL: Timespec = Timespec { sec: 1, nsec: 0 };

struct ShardedSlabCfg;
impl sharded_slab::Config for ShardedSlabCfg {
    const MAX_THREADS: usize = 64;

    // Ensure it fits in u64
    #[cfg(target_pointer_width = "64")]
    const RESERVED_BITS: usize = (std::mem::size_of::<usize>() - std::mem::size_of::<u64>()) * 8;
    #[cfg(target_pointer_width = "32")]
    const RESERVED_BITS: usize = 0;
}

type Slab<T> = sharded_slab::Slab<T, ShardedSlabCfg>;

struct ZboxFs {
    r: Mutex<Repo>,
    fhs: Slab<Mutex<File>>,
}

impl FilesystemMT for ZboxFs {
    fn init(&self, _req: RequestInfo) -> ResultEmpty {
        Ok(())
    }
    fn getattr(&self, _req: RequestInfo, path: &Path, _fh: Option<u64>) -> ResultEntry {
        let r = self.r.lock().map_err(|_| libc::ENOLCK)?;
        match r.metadata(path) {
            Ok(m) => Ok((TTL, zmeta2fa(m))),
            Err(e) => Err(ze2errno(e)),
        }
    }
    fn create(
        &self,
        _req: RequestInfo,
        parent: &Path,
        name: &OsStr,
        _mode: u32,
        flags: u32,
    ) -> ResultCreate {
        let fl = flags as libc::c_int;
        let oo = flags2openoptions(fl);

        let p = parent.join(name);
        let f;
        {
            let mut r = self.r.lock().map_err(|_| libc::ENOLCK)?;
            f = oo.open(&mut r, p).map_err(ze2errno)?;
        }
        let m = f.metadata().map_err(ze2errno)?;

        let fh = self.fhs.insert(Mutex::new(f)).ok_or(libc::ENOSR)?;
        let fh = fh as u64; // should be safe because of RESERVED_BITS

        Ok(CreatedEntry {
            ttl: TTL,
            attr: zmeta2fa(m),
            fh,
            flags: 0,
        })
    }
    fn open(&self, _req: RequestInfo, p: &Path, flags: u32) -> ResultOpen {
        let fl = flags as libc::c_int;
        let oo = flags2openoptions(fl);

        let f;
        {
            let mut r = self.r.lock().map_err(|_| libc::ENOLCK)?;
            f = oo.open(&mut r, p).map_err(ze2errno)?;
        }

        let fh = self.fhs.insert(Mutex::new(f)).ok_or(libc::ENOSR)?;
        let fh = fh as u64; // should be safe because of RESERVED_BITS

        Ok((fh, 1))
    }
    fn release(
        &self,
        _req: RequestInfo,
        _path: &Path,
        fh: u64,
        _flags: u32,
        _lock_owner: u64,
        _flush: bool,
    ) -> ResultEmpty {
        let f = match self.fhs.take(fh as usize) {
            None => return Err(libc::EBADF),
            Some(x) => x,
        };
        let mut f = f.into_inner().map_err(|_| libc::ENOLCK)?;

        match f.finish() {
            Ok(()) => (),
            Err(e) if e == zbox::Error::NotWrite => (),
            Err(e) => return Err(ze2errno(e)),
        }

        drop(f);

        Ok(())
    }
    fn fsync(&self, _req: RequestInfo, _path: &Path, fh: u64, _datasync: bool) -> ResultEmpty {
        let f = match self.fhs.get(fh as usize) {
            None => return Err(libc::EBADF),
            Some(x) => x,
        };
        let mut f = f.lock().map_err(|_| libc::ENOLCK)?;

        match f.finish() {
            Ok(()) => (),
            Err(e) if e == zbox::Error::NotWrite => (),
            Err(e) => return Err(ze2errno(e)),
        }

        Ok(())
    }
    fn read(
        &self,
        _req: RequestInfo,
        _path: &Path,
        fh: u64,
        offset: u64,
        size: u32,
        result: impl FnOnce(std::result::Result<&[u8], libc::c_int>),
    ) {
        let f = match self.fhs.get(fh as usize) {
            None => return result(Err(libc::EBADF)),
            Some(x) => x,
        };
        let mut f = match f.lock().map_err(|_| libc::ENOLCK) {
            Ok(x) => x,
            Err(e) => return result(Err(e)),
        };
        use std::io::{Read, Seek};

        let pos = match f.seek(std::io::SeekFrom::Start(offset)) {
            Err(e) => return result(Err(ie2errno(e))),
            Ok(x) => x,
        };

        if pos != offset {
            error!("Some seeking games are not implemented");
            return result(Err(libc::ENOSYS));
        }

        let mut buf: Vec<u8> = vec![0; size as usize];

        let rr = match (f.read(&mut buf)) {
            Err(e) => return result(Err(ie2errno(e))),
            Ok(x) => x,
        };

        let buf = &buf[0..rr];

        result(Ok(buf))
    }
    fn write(
        &self,
        _req: RequestInfo,
        _path: &Path,
        fh: u64,
        offset: u64,
        data: Vec<u8>,
        _flags: u32,
    ) -> ResultWrite {
        let f = match self.fhs.get(fh as usize) {
            None => return Err(libc::EBADF),
            Some(x) => x,
        };
        let mut f = f.lock().map_err(|_| libc::ENOLCK)?;

        use std::io::{Write, Seek};

        let pos = f.seek(std::io::SeekFrom::Start(offset)).map_err(ie2errno)?;

        if pos != offset {
            error!("Some seeking games are not implemented");
            Err(libc::ENOSYS)?;
        }

        let wr = f.write(&data[..]).map_err(ie2errno)?;

        Ok(wr as u32)
    }
    fn truncate(
        &self,
        _req: RequestInfo,
        path: &Path,
        fh: Option<u64>,
        size: u64
    ) -> ResultEmpty {
        let fh = match fh {
            Some(x) => x,
            None => {
                let mut f;
                {
                    let mut r = self.r.lock().map_err(|_| libc::ENOLCK)?;
                    f = OpenOptions::new().write(true).open(&mut r, path).map_err(ze2errno)?;
                }
                if (size  > std::usize::MAX as u64) {
                    return Err(libc::E2BIG);
                }
                f.set_len(size as usize);
                return Ok(())
            }
        };

        let f = match self.fhs.get(fh as usize) {
            None => return Err(libc::EBADF),
            Some(x) => x,
        };
        let mut f = f.lock().map_err(|_| libc::ENOLCK)?;

        if (size  > std::usize::MAX as u64) {
            return Err(libc::E2BIG);
        }

        f.set_len(size as usize).map_err(ze2errno)?;

        Ok(())
    }

    fn opendir(&self, _req: RequestInfo, path: &Path, _flags: u32) -> ResultOpen {
        let mut r = self.r.lock().map_err(|_| libc::ENOLCK)?;
        let m = r.metadata(path).map_err(ze2errno)?;
        if m.file_type() == zbox::FileType::Dir {
            Ok((0,0))
        } else {
            Err(libc::ENOTDIR)
        }
    }

    fn readdir(&self, _req: RequestInfo, path: &Path, _fh: u64) -> ResultReaddir {
        let mut r = self.r.lock().map_err(|_| libc::ENOLCK)?;
        use std::os::unix::ffi::OsStringExt;
        Ok(r.read_dir(path).map_err(ze2errno)?.iter().map(|zd| fuse_mt::DirectoryEntry {
            name: zd.file_name().into(),
            kind: zft2fft(zd.metadata().file_type()),
        }).collect() )
    }
    fn mkdir(
        &self,
        _req: RequestInfo,
        parent: &Path,
        name: &OsStr,
        _mode: u32
    ) -> ResultEntry {
        let p = parent.join(name);

        let mut r = self.r.lock().map_err(|_| libc::ENOLCK)?;
        r.create_dir(&p).map_err(ze2errno)?;
        let m = r.metadata(p).map_err(ze2errno)?;
        Ok((TTL, zmeta2fa(m)))
    }

    fn unlink(
        &self,
        _req: RequestInfo,
        parent: &Path,
        name: &OsStr
    ) -> ResultEmpty {
        let p = parent.join(name);
        let mut r = self.r.lock().map_err(|_| libc::ENOLCK)?;
        r.remove_file(p).map_err(ze2errno)?;
        Ok(())
    }

    fn rmdir(&self, _req: RequestInfo, parent: &Path, name: &OsStr) -> ResultEmpty {
        let p = parent.join(name);
        let mut r = self.r.lock().map_err(|_| libc::ENOLCK)?;
        r.remove_dir(p).map_err(ze2errno)?;
        Ok(())
    }

    fn rename(
        &self,
        _req: RequestInfo,
        parent: &Path,
        name: &OsStr,
        newparent: &Path,
        newname: &OsStr
    ) -> ResultEmpty {
        let p1 = parent.join(name);
        let p2 = newparent.join(newname);
        let mut r = self.r.lock().map_err(|_| libc::ENOLCK)?;
        r.rename(p1,p2).map_err(ze2errno)?;
        Ok(())
    }

    fn utimens(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _fh: Option<u64>,
        _atime: Option<Timespec>,
        _mtime: Option<Timespec>
    ) -> ResultEmpty {
        Ok(())
    }

    fn flush(
        &self,
        _req: RequestInfo,
        _path: &Path,
        _fh: u64,
        _lock_owner: u64
    ) -> ResultEmpty {
        Ok(())
    }
    fn getxattr(
        &self,
        _req: RequestInfo,
        path: &Path,
        name: &OsStr,
        size: u32
    ) -> ResultXattr {
        use fuse_mt::Xattr;
        let r = self.r.lock().map_err(|_| libc::ENOLCK)?;
        use std::borrow::Borrow;
        match name.to_string_lossy().borrow() {
            "zbox.curr_version" => {
                if size == 0 {
                    Ok(Xattr::Size(20))
                } else {
                    let m = r.metadata(path).map_err(ze2errno)?;
                    Ok(Xattr::Data(format!("{}",m.curr_version()).into_bytes()))
                }
            }
            "zbox.history" => {
                let h = r.history(path).map_err(ze2errno)?;
                if size == 0 {
                    Ok(Xattr::Size(80 * h.len() as u32))
                } else {
                    Ok(Xattr::Data(h.iter().map(|v| 
                        format!("{},{},{}\n", v.num(), v.content_len(), humantime::format_rfc3339_seconds(v.created_at()))
                    ).collect::<Vec<_>>().join("").into_bytes()))
                }
            }
            _ => Err(libc::ENODATA)
        }
    }
    fn listxattr(&self, _req: RequestInfo, _path: &Path, size: u32) -> ResultXattr {
        use fuse_mt::Xattr;
        if size == 0 {
            Ok(Xattr::Size(1024))
        } else {
            Ok(Xattr::Data(b"\
zbox.curr_version\0\
zbox.history\0\
".to_vec()))
        }
    }
}

pub fn mount<'q>(
    repo: Repo,
    path: impl AsRef<Path>,
    fuse_opts: impl AsRef<[&'q OsStr]>,
    threads: usize,
) -> Result<()> {
    let zboxfs = ZboxFs {
        r: Mutex::new(repo),
        fhs: sharded_slab::Slab::new_with_config(),
    };
    let mt = fuse_mt::FuseMT::new(zboxfs, threads);
    fuse_mt::mount(mt, &path, fuse_opts.as_ref())?;
    Ok(())
}
