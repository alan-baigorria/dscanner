#!/bin/bash
# dScanner - Escaneo rápido y compacto
# Uso: bash dscanner.sh <dominio> [-e]

set -eo pipefail

# Colores minimalistas
readonly G='\033[0;32m'  # Green
readonly Y='\033[1;33m'  # Yellow
readonly C='\033[0;36m'  # Cyan
readonly R='\033[0;31m'  # Red
readonly NC='\033[0m'    # No Color

# Config
TARGET="${1:-}"
EXPORT_TXT=false

# Parsear opciones
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--export)
            EXPORT_TXT=true
            shift
            ;;
        *)
            if [ -z "$TARGET" ]; then
                TARGET="$1"
            fi
            shift
            ;;
    esac
done

# Validación
if [ -z "$TARGET" ]; then
    echo -e "${R}Error: Dominio requerido${NC}"
    echo "Uso: $0 <dominio> [-e]"
    exit 1
fi

# Sanitizar dominio
TARGET=$(echo "$TARGET" | sed 's|https\?://||' | sed 's|/.*||')
REPORT="$(echo "$TARGET" | sed 's/\./-/g').txt"

############################
# FUNCIÓN: Extraer dominio raíz
############################
get_root_domain() {
    local domain="$1"
    domain=$(echo "$domain" | sed 's|https\?://||' | sed 's|/.*||')
    
    if echo "$domain" | grep -qE '\.(co\.|com\.|org\.|net\.|gov\.|edu\.)[a-z]{2}$'; then
        echo "$domain" | awk -F. '{print $(NF-2)"."$(NF-1)"."$NF}'
    else
        echo "$domain" | awk -F. '{print $(NF-1)"."$NF}'
    fi
}

# Header
echo -e "\n${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${Y}🔍 Scanner - UGR: ${G}${TARGET}${NC}"
echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

############################
# DNS - Resolución IPv4 e IPv6
############################
echo -e "[DNS RESOLUTION]"
IPS=$(dig +short +tries=2 +time=2 A "$TARGET" 2>/dev/null | grep -E '^[0-9]+\.' | paste -sd ',' - || echo "No resuelto")
IPS6=$(dig +short +tries=2 +time=2 AAAA "$TARGET" 2>/dev/null | grep -E '^[0-9a-fA-F:]+' | paste -sd ',' - || echo "")
echo -e "  IPv4: ${G}${IPS}${NC}"
[ -n "$IPS6" ] && echo -e "  IPv6: ${G}${IPS6}${NC}"

############################
# INICIAR NMAP EN SEGUNDO PLANO INMEDIATAMENTE
############################
nmap -T4 --open -sV -F --max-retries 1 "$TARGET" 2>/dev/null > /tmp/nmap_$.tmp &
NMAP_PID=$!

############################
# HTTPX - Tecnologías y info web
############################
echo -e "\n[WEB TECHNOLOGIES]"
if command -v httpx &> /dev/null; then
    HTTPX_OUTPUT=$(echo "$TARGET" | httpx -silent -td -server -title -status-code -cl -timeout 10 2>/dev/null || echo "")
    
    if [ -n "$HTTPX_OUTPUT" ]; then
        TECH=$(echo "$HTTPX_OUTPUT" | grep -oP '\[.*?\]' | tail -1 | tr -d '[]' || echo "")
        SERVER=$(echo "$HTTPX_OUTPUT" | grep -oP 'server:\K[^\s]+' || echo "")
        STATUS=$(echo "$HTTPX_OUTPUT" | grep -oP '\[\K[0-9]{3}(?=\])' | head -1 || echo "")
        TITLE=$(echo "$HTTPX_OUTPUT" | grep -oP 'title:\K[^\]]+' | head -1 | xargs || echo "")
        
        [ -n "$STATUS" ] && echo -e "  Status: ${G}$STATUS${NC}"
        [ -n "$TITLE" ] && echo -e "  Title: ${G}$TITLE${NC}"
        [ -n "$SERVER" ] && echo -e "  Server: ${G}$SERVER${NC}"
        [ -n "$TECH" ] && echo -e "  Tech: ${G}$TECH${NC}"
    else
        echo -e "  ${Y}No response${NC}"
    fi
else
    HEADERS=$(curl -sI "https://$TARGET" 2>/dev/null || curl -sI "http://$TARGET" 2>/dev/null || echo "")
    
    if [ -n "$HEADERS" ]; then
        STATUS=$(echo "$HEADERS" | head -1 | grep -oP '\d{3}' | head -1 || echo "")
        SERVER=$(echo "$HEADERS" | grep -i "^server:" | cut -d: -f2- | xargs || echo "N/A")
        POWERED=$(echo "$HEADERS" | grep -i "^x-powered-by:" | cut -d: -f2- | xargs || echo "")
        
        [ -n "$STATUS" ] && echo -e "  Status: ${G}$STATUS${NC}"
        [ "$SERVER" != "N/A" ] && echo -e "  Server: ${G}$SERVER${NC}"
        [ -n "$POWERED" ] && echo -e "  Powered-By: ${G}$POWERED${NC}"
    else
        echo -e "  ${Y}No response${NC}"
    fi
fi

############################
# ROBOTS.TXT y SITEMAP.XML - CORREGIDO
############################
echo -e "\n[CONTENT DISCOVERY]"

# Probar robots.txt - DETECCIÓN MEJORADA
ROBOTS_FOUND=false
ROBOTS_URLS=("https://$TARGET/robots.txt" "http://$TARGET/robots.txt" "https://www.$TARGET/robots.txt" "http://www.$TARGET/robots.txt")
ROBOTS_CONTENT=""

for url in "${ROBOTS_URLS[@]}"; do
    # Verificar primero el código de estado
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -L -A "Mozilla/5.0" "$url" 2>/dev/null || echo "000")
    
    if [ "$HTTP_STATUS" = "200" ]; then
        ROBOTS_CONTENT=$(curl -sL -A "Mozilla/5.0" "$url" 2>/dev/null)
        # Verificar que el contenido tenga líneas válidas de robots.txt
        if echo "$ROBOTS_CONTENT" | grep -qiE "^(user-agent|disallow|allow|sitemap| crawl-delay):" ; then
            ROBOTS_FOUND=true
            ROBOTS_URL="$url"
            break
        fi
    fi
done

if [ "$ROBOTS_FOUND" = true ]; then
    echo -e "  ${G}robots.txt encontrado${NC}"
    
    # Extraer rutas de Disallow (excluyendo solo "/")
    DISALLOW_PATHS=$(echo "$ROBOTS_CONTENT" | grep -i '^disallow:' | cut -d: -f2- | sed 's/^[[:space:]]*//' | grep -v '^[[:space:]]*$' | grep -v '^/$' | head -10)
    
    if [ -n "$DISALLOW_PATHS" ]; then
        echo -e "  ${Y}Rutas bloqueadas:${NC}"
        echo "$DISALLOW_PATHS" | while read -r path; do
            [ -n "$path" ] && echo -e "    ${C}➜${NC} $path"
        done
    else
        echo -e "  ${Y}No hay rutas específicas bloqueadas${NC}"
    fi
else
    echo -e "  ${Y}robots.txt no encontrado${NC}"
fi

# Buscar sitemap - DETECCIÓN MEJORADA
SITEMAP_FOUND=false

# Primero buscar sitemap en robots.txt si se encontró
if [ "$ROBOTS_FOUND" = true ]; then
    SITEMAP_FROM_ROBOTS=$(echo "$ROBOTS_CONTENT" | grep -i '^sitemap:' | cut -d: -f2- | sed 's/^[[:space:]]*//' | head -1)
    if [ -n "$SITEMAP_FROM_ROBOTS" ]; then
        # Verificar que el sitemap sea accesible
        SITEMAP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -L -A "Mozilla/5.0" "$SITEMAP_FROM_ROBOTS" 2>/dev/null || echo "000")
        if [ "$SITEMAP_STATUS" = "200" ]; then
            SITEMAP_URL="$SITEMAP_FROM_ROBOTS"
            SITEMAP_FOUND=true
        fi
    fi
fi

# Si no se encontró en robots.txt, probar URLs directas
if [ "$SITEMAP_FOUND" = false ]; then
    SITEMAP_URLS=("https://$TARGET/sitemap.xml" "http://$TARGET/sitemap.xml" "https://www.$TARGET/sitemap.xml" "http://www.$TARGET/sitemap.xml")
    
    for url in "${SITEMAP_URLS[@]}"; do
        SITEMAP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -L -A "Mozilla/5.0" "$url" 2>/dev/null || echo "000")
        if [ "$SITEMAP_STATUS" = "200" ]; then
            SITEMAP_URL="$url"
            SITEMAP_FOUND=true
            break
        fi
    done
fi

if [ "$SITEMAP_FOUND" = true ]; then
    echo -e "  ${G}sitemap.xml encontrado${NC}"
else
    echo -e "  ${Y}sitemap.xml no encontrado${NC}"
fi

############################
# COOKIES - Tabla ASCII
############################
echo -e "\n[COOKIE ANALYSIS]"

COOKIE_HEADERS=""
URLS_TO_TEST=("https://$TARGET" "http://$TARGET" "https://www.$TARGET" "http://www.$TARGET")

for url in "${URLS_TO_TEST[@]}"; do
    TEMP_HEADERS=$(curl -sL -I -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" "$url" 2>/dev/null | grep -i "^set-cookie:" || echo "")
    if [ -n "$TEMP_HEADERS" ]; then
        COOKIE_HEADERS="$TEMP_HEADERS"
        break
    fi
done

if [ -z "$COOKIE_HEADERS" ]; then
    for url in "${URLS_TO_TEST[@]}"; do
        TEMP_HEADERS=$(curl -sL -D - -o /dev/null -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" "$url" 2>/dev/null | grep -i "^set-cookie:" || echo "")
        if [ -n "$TEMP_HEADERS" ]; then
            COOKIE_HEADERS="$TEMP_HEADERS"
            break
        fi
    done
fi

if [ -n "$COOKIE_HEADERS" ]; then
    echo -e "  ${G}Cookies detectadas${NC}"
    
    printf "  ┌─────────────────────────┬──────────┬────────┬──────────┐\n"
    printf "  │ %-23s │ HttpOnly │ Secure │ SameSite │\n" "Name"
    printf "  ├─────────────────────────┼──────────┼────────┼──────────┤\n"
    
    echo "$COOKIE_HEADERS" | while IFS= read -r cookie_line; do
        cookie_data=$(echo "$cookie_line" | sed 's/^[Ss]et-[Cc]ookie: *//')
        cookie_name=$(echo "$cookie_data" | cut -d'=' -f1 | xargs | cut -c1-23)
        
        httponly="No"
        secure="No"
        samesite="None"
        
        echo "$cookie_data" | grep -iq "httponly" && httponly="Yes"
        echo "$cookie_data" | grep -iq "secure" && secure="Yes"
        
        samesite_val=$(echo "$cookie_data" | grep -ioP 'samesite=\K[^;]+' | xargs || echo "")
        [ -n "$samesite_val" ] && samesite="$samesite_val"
        
        printf "  │ %-23s │ %-8s │ %-6s │ %-8s │\n" "$cookie_name" "$httponly" "$secure" "$samesite"
    done
    
    printf "  └─────────────────────────┴──────────┴────────┴──────────┘\n"
else
    echo -e "  ${Y}No se detectaron cookies${NC}"
fi

############################
# ESPERAR Y MOSTRAR RESULTADOS DE NMAP
############################
echo -e "\n[PORT SCAN RESULTS]"
wait $NMAP_PID 2>/dev/null
NMAP_OUTPUT=$(cat /tmp/nmap_$.tmp 2>/dev/null || echo "")
rm -f /tmp/nmap_$.tmp

if [ -n "$NMAP_OUTPUT" ] && echo "$NMAP_OUTPUT" | grep -q "open"; then
    printf "  ┌────────┬────────┬────────────────────────────────────────┐\n"
    printf "  │ Puerto │ Estado │ Servicio/Versión                       │\n"
    printf "  ├────────┼────────┼────────────────────────────────────────┤\n"
    
    echo "$NMAP_OUTPUT" | grep 'open' | while read -r line; do
        PORT=$(echo "$line" | awk -F'/' '{print $1}')
        STATE=$(echo "$line" | awk '{print $2}')
        SERVICE=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | sed 's/^ *//' | xargs)
        SERVICE=$(echo "$SERVICE" | cut -c1-38)
        
        printf "  │ %-6s │ %-6s │ %-38s │\n" "$PORT" "$STATE" "$SERVICE"
    done
    
    printf "  └────────┴────────┴────────────────────────────────────────┘\n"
else
    echo -e "  ${Y}No se encontraron puertos abiertos${NC}"
fi

############################
# WHOIS - Solo para dominios raíz
############################
echo -e "\n[DOMAIN INFORMATION]"
ROOT_DOMAIN=$(get_root_domain "$TARGET")

if [ "$TARGET" = "$ROOT_DOMAIN" ]; then
    WHOIS_DATA=$(whois "$ROOT_DOMAIN" 2>/dev/null || echo "")

    REGISTRAR=$(echo "$WHOIS_DATA" | grep -im 1 'registrar:' | cut -d: -f2- | xargs || echo "N/A")
    CREATED=$(echo "$WHOIS_DATA" | grep -im 1 'creation date:' | cut -d: -f2- | awk '{print $1}' | sed 's/T.*//' || echo "N/A")
    EXPIRES=$(echo "$WHOIS_DATA" | grep -im 1 'expir' | cut -d: -f2- | awk '{print $1}' | sed 's/T.*//' || echo "N/A")
    NAMESERVERS=$(echo "$WHOIS_DATA" | grep -iE '^name server:' | awk '{print $NF}' | paste -sd ',' - || echo "N/A")

    if [[ "$CREATED" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        CREATED=$(echo "$CREATED" | awk -F'-' '{print $3"/"$2"/"$1}')
    fi
    if [[ "$EXPIRES" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        EXPIRES=$(echo "$EXPIRES" | awk -F'-' '{print $3"/"$2"/"$1}')
    fi

    echo -e "  Registrar: ${G}$REGISTRAR${NC}"
    echo -e "  Registro - Vencimiento: ${G}${CREATED:-N/A} - ${EXPIRES:-N/A}${NC}"
    echo -e "  Name Server(s): ${C}${NAMESERVERS:-N/A}${NC}"
else
    echo -e "  ${Y}Subdominio detectado - WHOIS no disponible${NC}"
fi

############################
# Exportar a TXT solo si se solicita
############################
if [ "$EXPORT_TXT" = true ]; then
    echo -e "\n[EXPORT]"
    {
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🔍 Scanner - UGR: $TARGET"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo

        echo "Las IPs son:"
        echo "  IPv4: ${IPS:-No resuelto}"
        [ -n "$IPS6" ] && echo "  IPv6: ${IPS6}"

        echo
        echo "Puertos y servicios detectados:"
        if [ -n "$NMAP_OUTPUT" ] && echo "$NMAP_OUTPUT" | grep -q "open"; then
            echo "$NMAP_OUTPUT" | grep 'open' | while read -r line; do
                PORT=$(echo "$line" | awk -F'/' '{print $1}')
                SERVICE=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | sed 's/^ *//' | xargs)
                echo "  Puerto $PORT: $SERVICE"
            done
        else
            echo "  Ninguno detectado"
        fi

        echo
        echo "Tecnologías detectadas:"
        [ -n "$STATUS" ] && echo "  Status: $STATUS"
        [ -n "$TITLE" ] && echo "  Title: $TITLE"
        [ -n "$SERVER" ] && echo "  Server: $SERVER"
        [ -n "$TECH" ] && echo "  Tech: $TECH"

        echo
        echo "Análisis de contenido:"
        if [ "$ROBOTS_FOUND" = true ]; then
            echo "  robots.txt: Encontrado"
            if [ -n "$DISALLOW_PATHS" ]; then
                echo "  Rutas bloqueadas:"
                echo "$DISALLOW_PATHS" | while read -r path; do
                    [ -n "$path" ] && echo "    - $path"
                done
            fi
        else
            echo "  robots.txt: No encontrado"
        fi
        [ "$SITEMAP_FOUND" = true ] && echo "  sitemap.xml: Encontrado"

        echo
        echo "Cookies:"
        if [ -n "$COOKIE_HEADERS" ]; then
            echo "$COOKIE_HEADERS" | while IFS= read -r cookie_line; do
                cookie_name=$(echo "$cookie_line" | sed 's/^[Ss]et-[Cc]ookie: *//' | cut -d'=' -f1 | xargs)
                echo "  - $cookie_name"
            done
        else
            echo "  No se detectaron cookies"
        fi

        if [ "$TARGET" = "$ROOT_DOMAIN" ]; then
            echo
            echo "Información del dominio:"
            echo "  Registrar: $REGISTRAR"
            echo "  Fecha de registro: $CREATED"
            echo "  Fecha de vencimiento: $EXPIRES"
            echo "  Nameservers: $NAMESERVERS"
        fi

        echo
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    } > "$REPORT"
    echo -e "  ${C}Reporte exportado: ${REPORT}${NC}"
fi

# Footer
echo -e "\n${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${G}Escaneo completado para: ${TARGET}${NC}"
echo -e "${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
