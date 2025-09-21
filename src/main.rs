

use std::ffi::CString;
use std::path::PathBuf;
use std::env;
use clap::Parser;

use std::ptr::null_mut;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessA, CreateRemoteThread, OpenProcessToken, PROCESS_INFORMATION,
    ResumeThread, STARTUPINFOA, WaitForSingleObject,
};
use windows::core::{Error, PSTR, s};

/// LoaderHonk - DLL Injector for game applications
#[derive(Parser)]
#[command(name = "loaderhonk")]
#[command(about = "Injector for hkrpg.dll into game processes")]
#[command(version = "1.0")]
struct Args {
    /// Path to the game executable (e.g., "StarRail.exe")
    #[arg(help = "Path to the target executable")]
    target_exe: Option<PathBuf>,
}

fn is_running_in_wine() -> bool {
    env::var("WINEBOTTLENAME").is_ok() || 
    env::var("WINELOADER").is_ok() || 
    env::var("WINEPREFIX").is_ok()
}

fn inject_standard(h_target: HANDLE, dll_path: &str) -> bool {
    unsafe {
        let loadlib = GetProcAddress(
            GetModuleHandleA(s!("kernel32.dll")).unwrap(),
            s!("LoadLibraryA"),
        )
        .unwrap();

        let dll_path_cstr = CString::new(dll_path).unwrap();
        let dll_path_addr = VirtualAllocEx(
            h_target,
            None,
            dll_path_cstr.to_bytes_with_nul().len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if dll_path_addr.is_null() {
            println!(
                "Failed allocating memory in the target process. GetLastError(): {:?}",
                GetLastError()
            );
            return false;
        }

        WriteProcessMemory(
            h_target,
            dll_path_addr,
            dll_path_cstr.as_ptr() as _,
            dll_path_cstr.to_bytes_with_nul().len(),
            None,
        )
        .unwrap();

        let h_thread = CreateRemoteThread(
            h_target,
            None,
            0,
            Some(std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
            >(loadlib)),
            Some(dll_path_addr),
            0,
            None,
        )
        .unwrap();

        WaitForSingleObject(h_thread, 0xFFFFFFFF);

        VirtualFreeEx(h_target, dll_path_addr, 0, MEM_RELEASE).unwrap();
        CloseHandle(h_thread).unwrap();
        true
    }
}

fn is_running_as_admin() -> Result<bool, Error> {
    unsafe {
        let mut token_handle = HANDLE::default();
        let current_process = windows::Win32::System::Threading::GetCurrentProcess();

        if OpenProcessToken(current_process, TOKEN_QUERY, &mut token_handle).is_err() {
            return Err(windows::core::Error::from_win32());
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;

        let success = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            size,
            &mut size,
        );

        let _ = CloseHandle(token_handle);

        if success.is_ok() {
            Ok(elevation.TokenIsElevated != 0)
        } else {
            Err(windows::core::Error::from_win32())
        }
    }
}

fn wait_exit() {
    println!("Press any key to exit...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

fn main() {
    let args = Args::parse();
    
    // Only check admin rights when actually injecting DLL
    // This allows --help and --version to work without admin rights

    let current_dir = std::env::current_dir().unwrap();
    let dll_path = current_dir.join("hkrpg.dll");
    if !dll_path.is_file() {
        println!("hkrpg.dll not found in current directory");
        wait_exit();
        return;
    }

    // Determine target executable
    let target_exe = if let Some(exe_path) = args.target_exe {
        // Use provided path
        if !exe_path.exists() {
            println!("❌ Error: Vị trí file '{}' không tồn tại hoặc không thể truy cập!", exe_path.display());
            println!("📁 Kiểm tra lại đường dẫn file thực thi");
            println!("💡 Gợi ý:");
            println!("   - Đảm bảo file tồn tại tại vị trí được chỉ định");
            println!("   - Sử dụng đường dẫn đầy đủ (absolute path)");
            println!("   - Kiểm tra quyền truy cập file");
            println!("📝 Ví dụ: loaderhonk.exe \"C:\\Games\\StarRail\\StarRail.exe\"");
            wait_exit();
            return;
        }
        
        // Validate that it's actually an executable file
        if let Some(extension) = exe_path.extension() {
            if extension.to_string_lossy().to_lowercase() != "exe" {
                println!("⚠️  Warning: File '{}' không phải là file .exe", exe_path.display());
                println!("🤔 Bạn có chắc chắn đây là file thực thi không?");
            }
        }
        
        exe_path
    } else {
        // Default to StarRail.exe in current directory
        let default_exe = current_dir.join("StarRail.exe");
        if !default_exe.exists() {
            println!("❌ Error: StarRail.exe không tìm thấy trong thư mục hiện tại");
            println!("📁 Thư mục hiện tại: {}", current_dir.display());
            println!("📝 Cách sử dụng:");
            println!("   loaderhonk.exe [đường_dẫn_file_thực_thi]");
            println!("💡 Ví dụ:");
            println!("   loaderhonk.exe \"StarRail.exe\"");
            println!("   loaderhonk.exe \"C:\\Games\\StarRail\\StarRail.exe\"");
            println!("   loaderhonk.exe \"D:\\HSR\\StarRail.exe\"");
            wait_exit();
            return;
        }
        default_exe
    };

    // Check admin rights before proceeding with injection
    // In Wine, admin checks might not work as expected, so we provide a warning
    let is_admin = is_running_as_admin().unwrap_or_default();
    let in_wine = is_running_in_wine();
    
    if !is_admin && !in_wine {
        println!("Error: launcher needs to be launched as admin for DLL injection");
        wait_exit();
        return;
    } else if !is_admin && in_wine {
        println!("Warning: Running in Wine - admin check skipped. Injection may fail if insufficient privileges.");
    }

    println!("Target executable: {}", target_exe.display());
    println!("DLL to inject: {}", dll_path.display());

    let mut proc_info = PROCESS_INFORMATION::default();
    let startup_info = STARTUPINFOA::default();

    // Convert path to CString for Windows API
    let exe_path_str = target_exe.to_string_lossy();
    let exe_path_cstring = match CString::new(exe_path_str.as_bytes()) {
        Ok(cstr) => cstr,
        Err(e) => {
            println!("Error: Invalid executable path: {}", e);
            wait_exit();
            return;
        }
    };

    unsafe {
        let result = CreateProcessA(
            PSTR(exe_path_cstring.as_ptr() as *mut u8),
            PSTR(null_mut()),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &startup_info,
            &mut proc_info,
        );

        match result {
            Ok(_) => {
                println!("Process created successfully");
                
                // Add a small delay for Wine compatibility
                if in_wine {
                    println!("⏳ Waiting 500ms for DLL initialization...");
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                
                if inject_standard(proc_info.hProcess, dll_path.to_str().unwrap()) {
                    println!("DLL injection successful");
                    
                    // Additional delay before resuming in Wine
                    if in_wine {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                    
                    ResumeThread(proc_info.hThread);
                    if in_wine {
                        println!("✅ Process resumed after initialization delay");
                    } else {
                        println!("Process resumed");
                    }
                } else {
                    println!("DLL injection failed");
                }

                CloseHandle(proc_info.hThread).unwrap();
                CloseHandle(proc_info.hProcess).unwrap();
            }
            Err(e) => {
                println!("Failed to create process: {:?}", e);
                println!("Error code: {:?}", GetLastError());
                if in_wine {
                    println!("Wine troubleshooting: Try running with 'winecfg' to check compatibility settings");
                }
                wait_exit();
            }
        }
    }
}
