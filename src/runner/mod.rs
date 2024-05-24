use nix::libc::{Elf32_Ehdr, Elf32_Phdr};
use std::arch::asm;
use std::env;
use std::ffi::CStr;
use std::sync::Mutex;

#[derive(Debug)]
pub struct Segment {
    address: usize,
    size: usize,
    file_offset: usize,
    file_size: usize,
    flags: nix::sys::mman::ProtFlags,
}

lazy_static::lazy_static! {
    static ref SEGMENTS: Mutex<Vec<Segment>> = Mutex::new(Vec::new());
}

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

    let mut auxv;

    let env_address = unsafe {
        let mut env = environ;

        while !(*env).is_null() {
            let arg: &CStr = CStr::from_ptr(*env as *const i8);
            let arg_slice: &str = arg.to_str().unwrap();
            println!("env {}", arg_slice);
            env = env.offset(1);
        }

        println!("printed arguments");

        env = env.offset(1);

        auxv = &mut *(env as *mut u8 as *mut Elf32AuxV);

        let argv = environ.offset(-(env::args().len() as isize + 2));

        *argv.offset(2) = *argv.offset(1);
        *argv.offset(1) = (env::args().len() - 1) as *mut u8;

        argv.offset(1)
    };

    while auxv.a_type != AT_NULL {
        match auxv.a_type {
            AT_PHDR => auxv.a_un.a_val = phdr as *const Elf32_Phdr as u32,
            AT_BASE => auxv.a_un.a_val = 0,
            AT_ENTRY => auxv.a_un.a_val = ehdr.e_entry,
            AT_EXECFN => auxv.a_un.a_val = 0,
            _ => {}
        }
        auxv = unsafe { &mut *(auxv as *mut Elf32AuxV).offset(1) };
    }

    unsafe {
        asm!(
            "mov esp, ebx
            xor ebx, ebx
            xor ecx, ecx
            xor edx, edx
            xor ebp, ebp
            xor esi, esi
            xor edi, edi
            jmp eax",
            in("eax") entry_point, in("ebx") env_address);
    }
}



