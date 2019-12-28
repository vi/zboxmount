use structopt::StructOpt;

use std::path::PathBuf;
use zbox::{RepoOpener, Cipher, OpsLimit, MemLimit};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

mod zboxfuse;

fn parse_cipher(x : &str) -> Result<Cipher> {
    match x {
        "xchaha" => Ok(Cipher::Xchacha),
        "aes" => Ok(Cipher::Aes),
        _ => Err("Cipher should be xchaha or aes")?
    }
}

fn parse_ops_limit(x : &str) -> Result<OpsLimit> {
    match x {
        "interactive" => Ok(OpsLimit::Interactive),
        "moderate" => Ok(OpsLimit::Moderate),
        "sensitive" => Ok(OpsLimit::Sensitive),
        _ => Err("Operations limit should be `interactive`, `moderate` or `sensitive`")?
    }
}

fn parse_mem_limit(x : &str) -> Result<MemLimit> {
    match x {
        "interactive" => Ok(MemLimit::Interactive),
        "moderate" => Ok(MemLimit::Moderate),
        "sensitive" => Ok(MemLimit::Sensitive),
        _ => Err("Meomry limit should be `interactive`, `moderate` or `sensitive`")?
    }
}

#[derive(StructOpt)]
struct Opt {
    /// Specify cipher when creating a repository. Value values are `xchaha` and `aes`.
    #[structopt(long="cipher", parse(try_from_str=parse_cipher))]
    cipher : Option<Cipher>,

    /// Override password hash operation limit. Valid values are `interactive`, `moderate` and `sensitive`.
    #[structopt(long="ops-limit", default_value="interactive", parse(try_from_str=parse_ops_limit))]
    ops_limit : OpsLimit,
    
    /// Override password hash operation limit. Valid values are `interactive`, `moderate` and `sensitive`.
    #[structopt(long="mem-limit", default_value="interactive", parse(try_from_str=parse_mem_limit))]
    mem_limit : MemLimit,

    /// Create repository if it not already exists
    #[structopt(long="create")]
    create: bool,

    /// Create repository, fail if it already exists
    #[structopt(long="create-new")]
    create_new: bool,

    /// Activate LZ4 compression
    #[structopt(long="compress")]
    compress: bool,

    /// Sets the default maximum number of file version.
    #[structopt(long="version-limit", default_value="1")]
    version_limit: u8,

    /// Activate deduplicator
    #[structopt(long="dedup-chunk")]
    dedup_chunk: bool,

    /// Open repository in read-only mode. You may also want `-- -o ro` FUSE option.
    #[structopt(long="readonly", short="r")]
    read_only: bool,

    /// Open repository regardless repo lock.
    #[structopt(long="force")]
    force: bool,

    /// Zbox URI to be opened or created. Example: `file:///tmp/myzbox/`
    uri : String,

    /// Specify plaintext password on command line. Not recommended for security.
    #[structopt(long="password")]
    password: Option<String>,

    /// Specify a file to read for password. Single trailing newline is chopped off.
    #[structopt(long="password-file", short="-p")]
    password_file: Option<PathBuf>,

    /// Location to mount FUSE filesystem at
    mountpoint: PathBuf,

    /// Rest of FUSE options, like `-o allow_others,ro`
    #[structopt(parse(from_os_str))]
    fuseopts: Vec<std::ffi::OsString>,

    /// Number of theads for Fuse-MT.
    #[structopt(long="threads", short="t", default_value="0")]
    threads: usize,
}

fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::from_args();

    if opt.password.is_some() && opt.password_file.is_some() {
        Err("Both --password and --password-file were specified")?;
    }

    zbox::init_env();

    let mut ro = RepoOpener::new();
    
    if let Some(ci) = opt.cipher {
        ro.cipher(ci);
    }
    ro.ops_limit(opt.ops_limit);
    ro.mem_limit(opt.mem_limit);
    ro.create(opt.create);
    ro.create_new(opt.create_new);
    ro.compress(opt.compress);
    ro.version_limit(opt.version_limit);
    ro.dedup_chunk(opt.dedup_chunk);
    ro.read_only(opt.read_only);
    ro.force(opt.force);

    let mut passwd : String = if let Some(pw) = opt.password {
        pw
    } else if let Some(pwf) = opt.password_file {
        let mut pw = String::with_capacity(64);
        use std::io::Read;
        std::fs::OpenOptions::new().read(true).open(pwf)?.read_to_string(&mut pw)?;
        if pw.ends_with('\n') { pw = pw[0..(pw.len()-1)].to_string(); }
        if pw.ends_with('\r') { pw = pw[0..(pw.len()-1)].to_string(); }
        pw
    } else {
        rpassword::prompt_password_stderr("Zbox repository password: ")?
    };

    let repo = ro.open(&opt.uri, &passwd)?;

    zeroize::Zeroize::zeroize(&mut passwd);

    let fuseopts_ref : Vec<&std::ffi::OsStr> = opt.fuseopts.iter().map(|x|x.as_ref()).collect();
    zboxfuse::mount(repo, opt.mountpoint, fuseopts_ref, opt.threads)
}
