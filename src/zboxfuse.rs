#![allow(unused)]
use std::ffi::OsStr;
use std::path::Path;
use zbox::Repo;
use fuse_mt::{FilesystemMT};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct ZboxFs(Repo);

impl FilesystemMT for ZboxFs {

}

pub fn mount<'q>(repo: Repo, path: impl AsRef<Path>, fuse_opts: impl AsRef<[&'q OsStr]>, threads: usize) -> Result<()> {
    let zboxfs = ZboxFs(repo);
    let mt = fuse_mt::FuseMT::new(zboxfs, threads);
    fuse_mt::mount(mt, &path, fuse_opts.as_ref())?;
    Ok(())
}
