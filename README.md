# dScanner 🔍

> Herramienta automatizada de reconocimiento web para auditorías de seguridad

## Descripción

dScanner consolida múltiples herramientas de reconocimiento en un solo comando para la fase inicial de pentesting web.

## 🚀 Instalación

### Opción 1: Descarga directa (Recomendado)
```bash Descargar el script
curl -o dscanner.sh https://raw.githubusercontent.com/alan-baigorria/dscanner/main/dscanner.sh
chmod +x dscanner.shEjecutar
./dscanner.sh google.com
```
## Desarrollo

Herramienta conceptualizada y diseñada para automatizar reconocimiento web 
en auditorías de seguridad. Desarrollada en bash con asistencia de Claude AI 
para implementación técnica y optimización.


**Características:**
- ✅ Resolución DNS con detección de subdominios
- ✅ Escaneo de puertos comunes (nmap)
- ✅ Detección de tecnologías (httpx/curl)
- ✅ Análisis de seguridad de cookies
- ✅ Información WHOIS (dominios raíz)
- ✅ Export a TXT con análisis de vulnerabilidades

## Arquitectura

| Módulo | Herramienta | Propósito |
|--------|-------------|-----------|
| DNS | dig | Resolver dominio a IPs |
| Web | httpx/curl | Detectar tecnologías y servidor |
| Puertos | nmap | Escanear puertos abiertos |
| Cookies | curl | Analizar atributos de seguridad |
| Registro | whois | Información del registrador |


## Instalación

# Escaneo básico
./dscanner.sh ejemplo.com

# Con export a TXT
./dscanner.sh ejemplo.com -e


# Ejemplo de salida:
<img width="756" height="559" alt="image" src="https://github.com/user-attachments/assets/2f261235-c396-424e-b47b-54eea76460bf" />

## Instalación
```bash
# Dependencias (Ubuntu/Debian)
sudo apt install dnsutils nmap curl whois

# Opcional: httpx (mejor detección)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
