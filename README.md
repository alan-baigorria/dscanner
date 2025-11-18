# dScanner 🔍

> Herramienta automatizada de reconocimiento web para auditorías de seguridad

## Descripción

dScanner consolida múltiples herramientas de reconocimiento en un solo comando para la fase inicial de pentesting web.

## 🚀 Instalación

Dependencias requeridas: curl dnsutils nmap whois golang httpx

Instalación de dependencias:
```bash
sudo apt install -y curl dnsutils nmap whois golang
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

```

```bash Descargar el script
curl -o dscanner.sh https://raw.githubusercontent.com/alan-baigorria/dscanner/main/dscanner.sh
chmod +x dscanner.shEjecutar
./bash dscanner.sh google.com
```
## Desarrollo

Herramienta conceptualizada y diseñada para automatizar reconocimiento web 
en auditorías de seguridad. Desarrollada en bash con asistencia de Claude AI 
para implementación técnica y optimización.

**Cosas que me gustaría hacer:**
- Reescribirlo en Python, agregar algo de certificado SSL
- Bypassear WAFS, tengo que sentarme y pedir las cookies de los distintos WAF pero conozco el de Cloudflare solamente

**Características:**
- ✅ Resolución DNS con detección de subdominios
- ✅ Escaneo de puertos comunes (nmap)
- ✅ Detección de tecnologías (httpx/curl)
- ✅ Análisis de seguridad de cookies
- ✅ Información WHOIS (dominios raíz)
- ✅ Analisis de robots.txt & sitemap.xml
- ✅ Analisis de cookies (
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


# Versiones
### 15/11/2025 - v1.5
- Agregué el scrapeo de robots.txt, sitemap.xml
- Cambié la configuración del nmap a -sV así se puede ver más información de cada puerto
- Ahora resuelve a IPv6


### 12/10/2025 - v1.0
- Primera versión de dscanner



# Ejemplo de salida:
![dscanner1](https://github.com/user-attachments/assets/278f6819-c9dc-4a15-a9d5-1c26de78b6ce)

<img width="756" height="559" alt="image" src="https://github.com/user-attachments/assets/2f261235-c396-424e-b47b-54eea76460bf" />

