use nix::libc::{Elf32_Ehdr, Elf32_Phdr};
use std::arch::asm;
use std::env;
use std::ffi::CStr;
use std::sync::Mutex;
use once_cell::sync::Lazy;

#[derive(Debug)]
pub struct Segment {
    pub address: usize,
    pub size: usize,
    pub file_offset: usize,
    pub file_size: usize,
    pub flags: nix::sys::mman::ProtFlags,
}

pub static SEGMENTS: Lazy<Mutex<Vec<Segment>>> = Lazy::new(|| Mutex::new(Vec::new()));

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Elf32AuxV {
    pub a_type: u32,
    pub a_un: Elf32AuxVBindgenTy1,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union Elf32AuxVBindgenTy1 {
    pub a_val: u32,
}

pub const AT_NULL: u32 = 0;
pub const AT_PHDR: u32 = 3;
pub const AT_BASE: u32 = 7;
pub const AT_ENTRY: u32 = 9;
pub const AT_EXECFN: u32 = 31;

extern "C" {
    static environ: *mut *mut u8;
}

pub fn exec_run(base_address: usize, entry_point: usize) {
    let ehdr = unsafe { &*(base_address as *const u8 as *const Elf32_Ehdr) };
    let phdr =
        unsafe { &*((base_address + (*ehdr).e_phoff as usize) as *const u8 as *const Elf32_Phdr) };

    let argv = vec![env::current_exe().unwrap().to_str().unwrap().as_ptr() as *const u8];
    let envp = unsafe { environ };

    let auxv = [
        Elf32AuxV {
            a_type: AT_PHDR,
            a_un: Elf32AuxVBindgenTy1 {
                a_val: base_address as u32 + ehdr.e_phoff,
            },
        },
        Elf32AuxV {
            a_type: AT_BASE,
            a_un: Elf32AuxVBindgenTy1 {
                a_val: base_address as u32,
            },
        },
        Elf32AuxV {
            a_type: AT_ENTRY,
            a_un: Elf32AuxVBindgenTy1 {
                a_val: entry_point as u32,
            },
        },
        Elf32AuxV {
            a_type: AT_EXECFN,
            a_un: Elf32AuxVBindgenTy1 {
                a_val: argv[0] as u32,
            },
        },
        Elf32AuxV {
            a_type: AT_NULL,
            a_un: Elf32AuxVBindgenTy1 { a_val: 0 },
        },
    ];

    unsafe {
        asm!(
            "mov eax, 0",
            "mov ebx, {0}",
            "mov ecx, {1}",
            "mov edx, {2}",
            "mov esi, {3}",
            "mov edi, {4}",
            "mov ebp, {5}",
            "jmp {6}",
            in(reg) argv.as_ptr(),
            in(reg) envp,
            in(reg) auxv.as_ptr(),
            in("esi") base_address,
            in("edi") entry_point,
            in("ebp") 0,
            in("eax") entry_point,
            options(noreturn)
        );
    }
}



