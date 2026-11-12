# EaseFilter Endpoint File Security SDK

[![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://www.easefilter.com/)
[![Language](https://img.shields.io/badge/Language-C%23%20%7C%20C%2B%2B%20%7C%20Python%20%7C%20Java%20%7C%20Rust-green.svg)](https://www.easefilter.com/kb/Programming.htm)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()

Build robust, zero-trust endpoint security solutions with deep, kernel-level visibility and control. The **EaseFilter Comprehensive File Security SDK** abstracts away the steep learning curve of Windows kernel development, empowering developers to engineer enterprise-grade endpoint security applications (like EDR, DLP, and Antivirus systems) using standard user-mode APIs.

---

## 🛡️ Why Kernel-Level Security?

Relying solely on standard Windows Access Control Lists (ACLs) is no longer sufficient to protect enterprise data. Sophisticated malware, ransomware, and insider threats can bypass traditional perimeter defenses and user-mode security hooks. 

By operating as a **Windows Minifilter Driver**, EaseFilter sits directly in the I/O stack. If a file operation occurs—whether it's a document being opened by Excel or a malicious binary attempting to encrypt a system directory—the kernel intercepts it. If the kernel doesn't see it, it didn't happen.

## 🏗️ Architecture

An endpoint security solution built with EaseFilter consists of core layers bridged by the SDK:
![endpoint security](https://www.easefilter.com/Images/endpoint-security-architecture.jpg)

1. **The Kernel Layer:** A minifilter driver that intercepts every single file operation (read, write, delete, execute) *before* it happens, offering total interception and tamper resistance.
2. **The User-Mode Layer:** Your custom application built with the SDK's APIs (C#, C++, Python, etc.) that evaluates rules and makes `Allow` or `Deny` decisions.

---

## ✨ Core Pillars & Practical Use Cases

### 1. Zero Trust Data Access (ZTDA) & Cryptographic Verification
Implement a "default deny" policy for highly sensitive directories. Allow access only for cryptographically verified binaries.

```csharp
FileFilterRule ztdaRule = new FileFilterRule(@"C:\Finance\*");

// 1. Deny all access by default
ztdaRule.AccessFlags = FilterAPI.AccessFlag.LEAST_ACCESS_RIGHT; 

// 2. Whitelist ONLY the verified custom application by signature/hash
ztdaRule.AddTrustedProcessRight(
    "ERP.exe", 
    FilterAPI.ALLOW_MAX_ACCESS_RIGHT, 
    "MyCompany-Digital-Signature", // Verifies certificate
    "A1B2C3D4E5..."                // Verifies SHA-256 hash
);

FilterControl.AddFilterRule(ztdaRule);
```

### 2. Adaptive Anti-Ransomware (The "Kill Switch")
Block malicious file operations proactively by monitoring file entropy (randomness) before data is written to the disk.

```csharp
FileFilterRule ransomwareRule = new FileFilterRule(@"C:\Users\*\Documents\*");
ransomwareRule.ControlFileIOEventFilter = (ulong)ControlFileIOEvents.OnPreFileWrite;

ransomwareRule.OnPreFileWrite += (sender, e) => 
{
    // High entropy often indicates encryption
    if (CalculateEntropy(e.FileName) > 7.5) 
    {
        // Block the write operation proactively
        e.ReturnStatus = NtStatus.Status.AccessDenied;
        TerminateProcess(e.ProcessId); // Trigger EDR kill-switch
    }
};
FilterControl.AddFilterRule(ransomwareRule);
```

### 3. Insider Threat & Data Loss Prevention (DLP)
Stop data theft via USB drives or network shares by intercepting `IRP_MJ_WRITE` requests for confidential files.

```csharp
FileFilterRule dlpRule = new FileFilterRule(@"E:\*"); // Target USB drive
dlpRule.ControlFileIOEventFilter = (ulong)ControlFileIOEvents.OnPreFileWrite;

dlpRule.OnPreFileWrite += (sender, e) => 
{
    if (HasConfidentialTag(e.FileName)) 
    {
        // Deny the kernel-level write request 
        e.ReturnStatus = NtStatus.Status.AccessDenied; 
    }
};
FilterControl.AddFilterRule(dlpRule);
```

### 4. Forensic Auditing (The "Black Box")
Capture unalterable, granular journal details for HIPAA or ISO 27001 compliance that user-mode logging often misses.

```csharp
FileFilterRule auditRule = new FileFilterRule(@"C:\PatientRecords\*");
auditRule.ControlFileIOEventFilter = (ulong)(ControlFileIOEvents.OnPostFileRead | 
                                             ControlFileIOEvents.OnPostFileWrite | 
                                             ControlFileIOEvents.OnPostFileRename);

auditRule.OnPostFileRead += (sender, e) => 
{
    string logEntry = $"[Audit] {e.UserName} ({e.ProcessName} - PID: {e.ProcessId}) " +
                      $"read {e.FileName} at {DateTime.UtcNow} | Status: {e.IoStatus}";
    LogToSIEM(logEntry);
};
FilterControl.AddFilterRule(auditRule);
```

### 5. Anti-Tampering (Self-Shielding)
Protect your security agent by making its installation directory immutable, even against local Administrator or SYSTEM accounts.

```csharp
FileFilterRule selfDefenseRule = new FileFilterRule(@"C:\Program Files\MyEnterpriseEDR\*");

// Remove Delete and Write flags by default
selfDefenseRule.AccessFlags = (FilterAPI.AccessFlag)(FilterAPI.ALLOW_MAX_ACCESS_RIGHT 
    & ~(uint)(FilterAPI.AccessFlag.ALLOW_FILE_DELETE | FilterAPI.AccessFlag.ALLOW_FILE_WRITE));

// Explicitly whitelist ONLY the updater service
selfDefenseRule.AddProcessRight("MyEDR_Updater.exe", FilterAPI.ALLOW_MAX_ACCESS_RIGHT);
FilterControl.AddFilterRule(selfDefenseRule);
```

## EaseFilter File System Filter Driver SDK Reference
| Product Name | Description |
| --- | --- |
| [Cloud File System SDK](https://www.easefilter.com/cloud/cloud-file-system-sdk.htm) | EaseFilter Cloud File System SDK Introduction. |
| [CloudTier Storage Tiering SDK](https://www.easefilter.com/cloud/storage-tiering-sdk.htm) | EaseFilter Storage Tiering Filter Driver SDK Introduction. |
| [File Monitor SDK](https://www.easefilter.com/kb/file-monitor-filter-driver-sdk.htm) | EaseFilter File Monitor Filter Driver SDK Introduction. |
| [File Control SDK](https://www.easefilter.com/kb/file-control-file-security-sdk.htm) | EaseFilter File Control Filter Driver SDK Introduction. |
| [File Encryption SDK](https://www.easefilter.com/kb/transparent-file-encryption-filter-driver-sdk.htm) | EaseFilter Transparent File Encryption Filter Driver SDK Introduction. |
| [Registry Filter SDK](https://www.easefilter.com/kb/registry-filter-drive-sdk.htm) | EaseFilter Registry Filter Driver SDK Introduction. |
| [Process Filter SDK](https://www.easefilter.com/kb/process-filter-driver-sdk.htm) | EaseFilter Process Filter Driver SDK Introduction. |
| [EaseFilter SDK Programming](https://www.easefilter.com/kb/programming.htm) | EaseFilter Filter Driver SDK Programming. |

## EaseFilter SDK Sample Projects
| Sample Project | Description |
| --- | --- |
| [CloudTier Storage Tiering Demo](https://www.easefilter.com/cloud/cloudtier-storage-tiering-demo.htm) | A HSM File System Filter Driver Demo. |
| [CloudTier S3 Tiering Demo](https://www.easefilter.com/cloud/cloudtier-s3-intelligent-tiering-demo.htm) | CloudTier S3 Intelligent Tiering Demo. |
| [Cloud File DR S3 Demo](https://www.easefilter.com/cloud/cloud-file-dr-demo.htm) | Cloud File DR S3 Demo. |
| [Amazon S3 File Explorer Demo](https://www.easefilter.com/cloud/s3-browser-demo.htm) | Amazon S3 File Explorer Demo. |
| [Auto File DRM Encryption](https://www.easefilter.com/kb/auto-file-drm-encryption-tool.htm) | Auto file encryption with DRM data embedded. |
| [Transparent File Encrypt](https://www.easefilter.com/kb/AutoFileEncryption.htm) | Transparent on access file encryption. |
| [Secure File Sharing with DRM](https://www.easefilter.com/kb/DRM_Secure_File_Sharing.htm) | Secure encrypted file sharing with digital rights management. |
| [File Monitor Example](https://www.easefilter.com/kb/file-monitor-demo.htm) | Monitor file system I/O in real time, tracking file changes. |
| [File Protector Example](https://www.easefilter.com/kb/file-protector-demo.htm) | Prevent sensitive files from being accessed by unauthorized users or processes. |
| [FolderLocker Example](https://www.easefilter.com/kb/FolderLocker.htm) | Lock file automatically in a FolderLocker. |
| [Process Monitor](https://www.easefilter.com/kb/Process-Monitor.htm) | Monitor the process creation and termination, block unauthorized process running. |
| [Registry Monitor](https://www.easefilter.com/kb/RegMon.htm) | Monitor the Registry activities, block the modification of the Registry keys. |
| [Secure Sandbox Example](https://www.easefilter.com/kb/Secure-Sandbox.htm) |A secure sandbox example, block the processes accessing the files out of the box. |
| [FileSystemWatcher Example](https://www.easefilter.com/kb/FileSystemWatcher.htm) | File system watcher, logging the file I/O events. |
| [ZeroTrust Example](https://www.easefilter.com/kb/zero-trust-file-access-control-demo.htm) | Zero trust file access control with encryption feature. |

## Filter Driver Reference

* [Understand MiniFilter Driver](https://www.easefilter.com/kb/understand-minifilter.htm)
* [Understand File I/O](https://www.easefilter.com/kb/File_IO.htm)
* [Understand I/O Request Packets(IRPs)](https://www.easefilter.com/kb/understand-irps.htm)
* [Filter Driver Developer Guide](https://www.easefilter.com/kb/DeveloperGuide.htm)
* [MiniFilter Filter Driver Framework](https://www.easefilter.com/kb/minifilter-framework.htm)
* [Isolation Filter Driver](https://www.easefilter.com/kb/Isolation_Filter_Driver.htm)

## License

This repository contains two distinct licensing categories:

1. **Wrapper/Implementation Code (MIT License):** 
   The source code, scripts, and configuration files provided directly in this repository are licensed under the [MIT License](LICENSE). You are free to modify, distribute, and use this specific integration code.

2. **EaseFilter SDK (Commercial License):**
   This project requires the EaseFilter SDK (including its binaries, filter drivers, and core libraries) to function. The EaseFilter SDK is **proprietary commercial software** and is strictly excluded from the MIT License.   
   To use the EaseFilter SDK for commercial purposes or in a production environment, you must obtain a valid commercial license directly from [EaseFilter](https://www.easefilter.com/license.pdf).


## Support
If you have questions or need help, please contact support@easefilter.com 

[Home](https://www.easefilter.com/) | [Solution](https://www.easefilter.com/solutions.htm) | [Download](https://www.easefilter.com/download.htm) | [Demos](https://www.easefilter.com/online-fileio-test.aspx) | [Blog](https://blog.easefilter.com/) | [Programming](https://www.easefilter.com/kb/programming.htm)
