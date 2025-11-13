# RedTeam-Bypass

## Volcado de la Base de Datos SAM / SAM Database Dumping

Este repositorio contiene documentación e implementaciones sobre el volcado de la base de datos SAM (Security Account Manager) de Windows en múltiples lenguajes de programación.

This repository contains documentation and implementations for dumping the Windows SAM (Security Account Manager) database in multiple programming languages.

### Documentación / Documentation

- **[DumpingTheSAM.md](DumpingTheSAM.md)** - Documentación completa en inglés sobre el proceso de volcado SAM / Complete English documentation on the SAM dumping process
- **[DumpingTheSAM_ES.md](DumpingTheSAM_ES.md)** - Documentación completa en español sobre el proceso de volcado SAM / Complete Spanish documentation on the SAM dumping process

### Implementaciones / Implementations

Este repositorio incluye implementaciones del proceso de volcado SAM en los siguientes lenguajes:

This repository includes implementations of the SAM dumping process in the following languages:

#### 1. PowerShell - [DumpSAM.ps1](DumpSAM.ps1)
```powershell
# Requiere ejecutar como Administrador / Requires running as Administrator
.\DumpSAM.ps1
```

**Características / Features:**
- Exporta claves de registro SAM y SYSTEM / Exports SAM and SYSTEM registry keys
- Habilita privilegios SeBackupPrivilege / Enables SeBackupPrivilege
- Compatible con Windows 7+ / Compatible with Windows 7+

#### 2. Bash - [DumpSAM.sh](DumpSAM.sh)
```bash
# Requiere ejecutar como root / Requires running as root
sudo ./DumpSAM.sh
```

**Características / Features:**
- Busca archivos SAM en sistemas Windows montados / Searches for SAM files in mounted Windows systems
- Copia archivos SAM y SYSTEM / Copies SAM and SYSTEM files
- Compatible con herramientas de extracción Linux / Compatible with Linux extraction tools

#### 3. Python - [DumpSAM.py](DumpSAM.py)
```bash
# Requiere Python 3.6+ / Requires Python 3.6+
python DumpSAM.py
# o con argumentos / or with arguments
python DumpSAM.py --sam /path/to/sam --system /path/to/system -o output_dir
```

**Características / Features:**
- Multiplataforma (Windows/Linux) / Cross-platform (Windows/Linux)
- Integración con Impacket para extracción / Impacket integration for extraction
- Argumentos de línea de comandos / Command-line arguments

#### 4. Go - [DumpSAM.go](DumpSAM.go)
```bash
# Compilar / Compile
go build DumpSAM.go

# Ejecutar / Run
./DumpSAM
```

**Características / Features:**
- Binario independiente / Standalone binary
- Multiplataforma / Cross-platform
- Sin dependencias externas / No external dependencies

#### 5. Rust - [DumpSAM.rs](DumpSAM.rs)
```bash
# Compilar / Compile
rustc DumpSAM.rs

# O con Cargo / Or with Cargo
cargo build --release

# Ejecutar / Run
./DumpSAM
```

**Características / Features:**
- Alto rendimiento / High performance
- Seguridad de memoria / Memory safety
- Binario optimizado / Optimized binary

### Requisitos / Requirements

Cada implementación requiere:
- **Privilegios de administrador/root** para acceder a archivos SAM
- **Permisos apropiados** en el sistema objetivo

Each implementation requires:
- **Administrator/root privileges** to access SAM files
- **Appropriate permissions** on the target system

### Herramientas de Extracción / Extraction Tools

Para extraer los hashes de los archivos SAM/SYSTEM exportados, puede usar:

To extract hashes from the exported SAM/SYSTEM files, you can use:

1. **secretsdump.py** (Impacket)
   ```bash
   pip install impacket
   secretsdump.py -sam sam.hive -system system.hive LOCAL
   ```

2. **samdump2** (Linux)
   ```bash
   apt-get install samdump2
   samdump2 system.hive sam.hive
   ```

3. **mimikatz** (Windows)
   ```
   lsadump::sam /sam:sam.hive /system:system.hive
   ```

### Propósito y Advertencias / Purpose and Warnings

⚠️ **ADVERTENCIA / WARNING:**
- Este código es **solo para fines educativos** y **pruebas de penetración autorizadas**
- El uso no autorizado en sistemas que no le pertenecen es **ilegal**
- El autor no se hace responsable del mal uso de este código

⚠️ **WARNING:**
- This code is **for educational purposes only** and **authorized penetration testing**
- Unauthorized use on systems you don't own is **illegal**
- The author is not responsible for misuse of this code

### Estructura del Repositorio / Repository Structure

```
RedTeam-Bypass/
├── README.md                 # Este archivo / This file
├── DumpingTheSAM.md         # Documentación en inglés / English documentation
├── DumpingTheSAM_ES.md      # Documentación en español / Spanish documentation
├── DumpSAM.ps1              # Implementación PowerShell / PowerShell implementation
├── DumpSAM.sh               # Implementación Bash / Bash implementation
├── DumpSAM.py               # Implementación Python / Python implementation
├── DumpSAM.go               # Implementación Go / Go implementation
└── DumpSAM.rs               # Implementación Rust / Rust implementation
```

### Contribuciones / Contributions

Las contribuciones son bienvenidas. Por favor, asegúrese de que cualquier código enviado:
- Sea educativo y esté bien documentado
- Siga las mejores prácticas de seguridad
- Incluya advertencias apropiadas sobre el uso ético

Contributions are welcome. Please ensure that any submitted code:
- Is educational and well-documented
- Follows security best practices
- Includes appropriate warnings about ethical use

### Licencia / License

Este proyecto es para fines educativos únicamente. Úselo de manera responsable y solo en sistemas para los que tiene autorización explícita.

This project is for educational purposes only. Use responsibly and only on systems you have explicit authorization to test.