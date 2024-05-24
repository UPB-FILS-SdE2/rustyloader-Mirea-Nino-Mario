use nix::libc::siginfo_t;
use std::error::Error;
use std::os::raw::{c_int, c_void};
use std::fs::File;
use std::io::Read;
use std::mem;
use std::ptr;
use std::sync::Mutex;

mod runner;
mod mod;

extern "C" fn sigsegv_handler(_signal: c_int, siginfo: *mut siginfo_t, _extra: *mut c_void) {
    let address = unsafe { (*siginfo).si_addr() } as usize;
    eprintln!("Page fault at address: 0x{:x}", address);

    let page_size = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE).unwrap().unwrap() as usize;
    let page_start = address & !(page_size - 1);

    let segments = SEGMENTS.lock().unwrap();
    let mut segment_found = false;

    for segment in segments.iter() {
        let seg_start = segment.address;
        let seg_end = seg_start + segment.size;

        if address >= seg_start && address < seg_end {
            segment_found = true;

            let offset = page_start - seg_start + segment.file_offset;
            let length = std::cmp::min(page_size, segment.file_size - offset);

            let data = &buffer[offset..offset + length];

            unsafe {
                let result = nix::sys::mman::mmap(
                    page_start as *mut c_void,
                    page_size,
                    segment.flags,
                    nix::sys::mman::MapFlags::MAP_FIXED | nix::sys::mman::MapFlags::MAP_PRIVATE | nix::sys::mman::MapFlags::MAP_ANONYMOUS,
                    -1,
                    0,
                );

                if result.is_err() {
                    eprintln!("Failed to map memory at address: 0x{:x}", page_start);
                    std::process::exit(-200);
                }

                let result = std::ptr::copy_nonoverlapping(data.as_ptr(), page_start as *mut u8, length);
                if result.is_err() {
                    eprintln!("Failed to copy data to mapped memory at address: 0x{:x}", page_start);
                    std::process::exit(-200);
                }
            }

            break;
        }
    }

    if !segment_found {
        eprintln!("Invalid memory access at address: 0x{:x}", address);
        std::process::exit(-200);
    }
}

fn exec(filename: &str) -> Result<(), Box<dyn Error>> {
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let elf = object::File::parse(&*buffer)?;

    eprintln!("Segments");
    let mut segments = Vec::new();
    for (i, segment) in elf.segments().enumerate() {
        eprintln!(
            "{}\t0x{:x}\t{}\t0x{:x}\t{}\t{}",
            i,
            segment.address(),
            segment.size(),
            segment.file_range().0,
            segment.file_range().1,
            if segment.is_executable() {
                "r-x"
            } else if segment.is_writable() {
                "rw-"
            } else {
                "r--"
            }
        );

        segments.push(Segment {
            address: segment.address() as usize,
            size: segment.size() as usize,
            file_offset: segment.file_range().0 as usize,
            file_size: segment.file_range().1 as usize,
            flags: if segment.is_executable() {
                nix::sys::mman::ProtFlags::PROT_EXEC | nix::sys::mman::ProtFlags::PROT_READ
            } else if segment.is_writable() {
                nix::sys::mman::ProtFlags::PROT_WRITE | nix::sys::mman::ProtFlags::PROT_READ
            } else {
                nix::sys::mman::ProtFlags::PROT_READ
            },
        });
    }

    let entry_point = elf.entry();
    let base_address = elf.segments().next().map(|seg| seg.address()).unwrap_or(0);

    eprintln!("Entry point: 0x{:x}", entry_point);
    eprintln!("Base address: 0x{:x}", base_address);

    {
        let mut segs = SEGMENTS.lock().unwrap();
        *segs = segments;
    }

    unsafe {
        let handler = nix::sys::signal::SigAction::new(
            nix::sys::signal::SigHandler::SigAction(sigsegv_handler),
            nix::sys::signal::SaFlags::SA_SIGINFO,
            nix::sys::signal::SigSet::empty(),
        );
        nix::sys::signal::sigaction(nix::sys::signal::SIGSEGV, &handler)?;
    }

    runner::exec_run(base_address, entry_point);

    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path_to_elf>", args[0]);
        std::process::exit(1);
    }

    exec(&args[1])
}
