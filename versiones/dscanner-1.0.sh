#!/bin/bash
# dScanner - Escaneo rápido y compacto
# Uso: bash dscanner.sh <dominio> [opciones]

set -eo pipefail  # Removido 'u' para evitar errores con variables no definidas

# Colores minimalistas
readonly G='\033[0;32m'  # Green
readonly Y='\033[1;33m'  # Yellow
readonly C='\033[0;36m'  # Cyan
readonly R='\033[0;31m'  # Red
readonly NC='\033[0m'    # No Color

# Config
TARGET="${1:-}"
VERBOSE=false
EXPORT_TXT=false
TIMEOUT=10

# Parsear opciones
shift 2>/dev/null || true
while [ $# -gt 0 ]; do
    case "$1" in
        -v|--verbose) VERBOSE=true ;;
        -e|--export) EXPORT_TXT=true ;;
        -t|--timeout) TIMEOUT="$2"; shift ;;
        *) echo -e "${R}Opción desconocida: $1${NC}" ;;
    esac
    shift 2>/dev/null || true
done

# Validación
if [ -z "$TARGET" ]; then
    echo -e "${R}Error: Dominio requerido${NC}"
    echo "Uso: $0 <dominio> [-v] [-e] [-t timeout]"
    echo "  -v, --verbose  : Modo detallado"
    echo "  -e, --export   : Exportar resultado a archivo TXT"
    echo "  -t, --timeout  : Timeout en segundos (default: 10)"
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
    # Remove protocol if present
    domain=$(echo "$domain" | sed 's|https\?://||' | sed 's|/.*||')
    
    # Handle multi-part TLDs like .co.uk, .com.ar, etc.
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
# DNS - Resolución rápida
############################
IPS=$(timeout "$TIMEOUT" dig +short +tries=2 +time=2 A "$TARGET" 2>/dev/null | grep -E '^[0-9]+\.' | paste -sd ',' - || echo "No resuelto")
echo -e "[IPS - dig]: ${G}${IPS}${NC}"

############################
# PUERTOS - Escaneo rápido (en paralelo con otras tareas)
############################
# Iniciar nmap en background para ganar tiempo
nmap -T5 --open -F --max-retries 1 "$TARGET" 2>/dev/null > /tmp/nmap_$.tmp &
NMAP_PID=$!

############################
# HTTPX - Tecnologías y info web
############################
echo
# Verificar si httpx está instalado
if command -v httpx &> /dev/null; then
    HTTPX_OUTPUT=$(echo "$TARGET" | httpx -silent -td -server -title -status-code -cl -timeout "$TIMEOUT" 2>/dev/null || echo "")
    
    if [ -n "$HTTPX_OUTPUT" ]; then
        # Extraer tecnologías detectadas
        TECH=$(echo "$HTTPX_OUTPUT" | grep -oP '\[.*?\]' | tail -1 | tr -d '[]' || echo "")
        # Extraer servidor
        SERVER=$(echo "$HTTPX_OUTPUT" | grep -oP 'server:\K[^\s]+' || echo "")
        # Extraer status code
        STATUS=$(echo "$HTTPX_OUTPUT" | grep -oP '\[\K[0-9]{3}(?=\])' | head -1 || echo "")
        
        echo -e "[WEB INFO - httpx]:"
        [ -n "$STATUS" ] && echo -e "  Status: ${G}$STATUS${NC}"
        [ -n "$SERVER" ] && echo -e "  Server: ${G}$SERVER${NC}"
        [ -n "$TECH" ] && echo -e "  Tech: ${G}$TECH${NC}"
    else
        echo -e "[WEB INFO - httpx]: ${Y}No response${NC}"
    fi
else
    # Fallback a curl si httpx no está instalado
    echo -e "[WEB INFO - curl fallback]:"
    HEADERS=$(timeout "$TIMEOUT" curl -sI "https://$TARGET" 2>/dev/null || timeout "$TIMEOUT" curl -sI "http://$TARGET" 2>/dev/null || echo "")
    
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
    
    echo -e "  ${Y}💡 Tip: Install httpx for better tech detection${NC}"
    echo -e "  ${C}   go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest${NC}"
fi

############################
# PUERTOS - Recolectar resultado de nmap
############################
echo
wait $NMAP_PID 2>/dev/null || true
NMAP_OUTPUT=$(cat /tmp/nmap_$.tmp 2>/dev/null || echo "")
rm -f /tmp/nmap_$.tmp
PORTS=$(echo "$NMAP_OUTPUT" | grep 'open' | awk -F'/' '{print $1}' | paste -sd ',' -)
echo -e "[PUERTOS ABIERTOS - nmap]: ${G}${PORTS:-Ninguno}${NC}"

############################
# COOKIES - Tabla ASCII
############################
echo
echo -e "[COOKIES - curl]:"

# Obtener headers con cookies (intentar HTTPS primero con user-agent y follow redirects)
COOKIE_HEADERS=$(timeout "$TIMEOUT" curl -sL -D - -o /dev/null -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" "https://$TARGET" 2>/dev/null | grep -i "^set-cookie:" || echo "")

if [ -z "$COOKIE_HEADERS" ]; then
    # Si falla HTTPS, intentar HTTP
    COOKIE_HEADERS=$(timeout "$TIMEOUT" curl -sL -D - -o /dev/null -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" "http://$TARGET" 2>/dev/null | grep -i "^set-cookie:" || echo "")
fi

if [ -z "$COOKIE_HEADERS" ]; then
    # Último intento: con www
    COOKIE_HEADERS=$(timeout "$TIMEOUT" curl -sL -D - -o /dev/null -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" "https://www.$TARGET" 2>/dev/null | grep -i "^set-cookie:" || echo "")
fi

if [ -n "$COOKIE_HEADERS" ]; then
    # Encabezado de la tabla
    printf "  ┌─────────────────────────┬──────────┬────────┬──────────┐\n"
    printf "  │ %-23s │ HttpOnly │ Secure │ SameSite │\n" "Name"
    printf "  ├─────────────────────────┼──────────┼────────┼──────────┤\n"
    
    # Procesar cada cookie
    echo "$COOKIE_HEADERS" | while IFS= read -r cookie_line; do
        # Extraer todo después de "Set-Cookie: "
        cookie_data=$(echo "$cookie_line" | sed 's/^[Ss]et-[Cc]ookie: *//')
        
        # Extraer nombre de la cookie (máximo 23 caracteres)
        cookie_name=$(echo "$cookie_data" | cut -d'=' -f1 | xargs | cut -c1-23)
        
        # Buscar atributos de seguridad importantes
        httponly="No"
        secure="No"
        samesite="None"
        
        if echo "$cookie_data" | grep -iq "httponly"; then
            httponly="Yes"
        fi
        
        if echo "$cookie_data" | grep -iq "secure"; then
            secure="Yes"
        fi
        
        samesite_val=$(echo "$cookie_data" | grep -ioP 'samesite=\K[^;]+' | xargs || echo "")
        if [ -n "$samesite_val" ]; then
            samesite="$samesite_val"
        fi
        
        # Imprimir fila de la tabla
        printf "  │ %-23s │ %-8s │ %-6s │ %-8s │\n" "$cookie_name" "$httponly" "$secure" "$samesite"
    done
    
    # Footer de la tabla
    printf "  └─────────────────────────┴──────────┴────────┴──────────┘\n"
else
    echo -e "  ${Y}No se detectaron cookies${NC}"
fi

############################
# WHOIS - Solo para dominios raíz
############################
echo
ROOT_DOMAIN=$(get_root_domain "$TARGET")

# Solo ejecutar WHOIS si es el dominio raíz (no subdominios)
if [ "$TARGET" = "$ROOT_DOMAIN" ]; then
    echo -e "[WHOIS]"
    WHOIS_DATA=$(timeout "$TIMEOUT" whois "$ROOT_DOMAIN" 2>/dev/null || echo "")

    REGISTRAR=$(echo "$WHOIS_DATA" | grep -im 1 'registrar:' | cut -d: -f2- | xargs || echo "N/A")
    CREATED=$(echo "$WHOIS_DATA" | grep -im 1 'creation date:' | cut -d: -f2- | awk '{print $1}' | sed 's/T.*//' || echo "N/A")
    EXPIRES=$(echo "$WHOIS_DATA" | grep -im 1 'expir' | cut -d: -f2- | awk '{print $1}' | sed 's/T.*//' || echo "N/A")
    NAMESERVERS=$(echo "$WHOIS_DATA" | grep -iE '^name server:' | awk '{print $NF}' | paste -sd ',' - || echo "N/A")

    # Convertir fechas a DD/MM/YYYY
    if [[ "$CREATED" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        CREATED=$(echo "$CREATED" | awk -F'-' '{print $3"/"$2"/"$1}')
    fi
    if [[ "$EXPIRES" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        EXPIRES=$(echo "$EXPIRES" | awk -F'-' '{print $3"/"$2"/"$1}')
    fi

    echo -e "  Registrar: ${G}$REGISTRAR${NC}"
    echo -e "  Registro - Vencimiento: ${G}${CREATED:-N/A} - ${EXPIRES:-N/A}${NC}"
    echo -e "  Name Server(s): ${C}${NAMESERVERS:-N/A}${NC}"
fi

############################
# Exportar a TXT limpio
############################
if [ "$EXPORT_TXT" = true ]; then
{
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🔍 Scanner - UGR: $TARGET"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo

    # Detección de Cloudflare
    IS_CLOUDFLARE=false
    if echo "$TECH" | grep -qi "cloudflare" || echo "$SERVER" | grep -qi "cloudflare"; then
        IS_CLOUDFLARE=true
    fi

    # IPs (modificar último octeto si es Cloudflare)
    if [ "$IS_CLOUDFLARE" = true ] && [ -n "$IPS" ] && [ "$IPS" != "No resuelto" ]; then
        # Reemplazar último octeto de cada IP con 1/255
        IPS_MODIFIED=$(echo "$IPS" | sed 's/\.[0-9]\+\(,\|$\)/\.1\/255\1/g')
        echo "Las IPs son: ${IPS_MODIFIED} (Cloudflare WAF detectado)"
    else
        echo "Las IPs son: ${IPS:-No resuelto}"
    fi

    # Puertos abiertos
    echo "Los puertos abiertos son: ${PORTS:-Ninguno}"

    # Tecnologías
    if [ -n "$TECH" ]; then
        echo "Las tecnologías utilizadas son: $TECH"
    elif [ -n "$SERVER" ]; then
        echo "Server detectado: $SERVER"
    else
        echo "Las tecnologías utilizadas son: No detectadas"
    fi

    # Cookies con análisis de vulnerabilidades
    echo
    echo "Cookies presentes son:"
    if [ -n "$COOKIE_HEADERS" ]; then
        VULNERABLE_COOKIES=()
        
        # Analizar cada cookie
        while IFS= read -r cookie_line; do
            cookie_data=$(echo "$cookie_line" | sed 's/^[Ss]et-[Cc]ookie: *//')
            cookie_name=$(echo "$cookie_data" | cut -d'=' -f1 | xargs)
            
            # Verificar atributos de seguridad
            httponly=0
            secure=0
            samesite="none"
            
            if echo "$cookie_data" | grep -iq "httponly"; then
                httponly=1
            fi
            
            if echo "$cookie_data" | grep -iq "secure"; then
                secure=1
            fi
            
            samesite_val=$(echo "$cookie_data" | grep -ioP 'samesite=\K[^;]+' | xargs || echo "")
            if [ -n "$samesite_val" ]; then
                samesite="$samesite_val"
            fi
            
            # Detectar cookies REALMENTE vulnerables (críticas)
            # Solo si falta httponly O secure (no samesite solo)
            if [ "$httponly" -eq 0 ] || [ "$secure" -eq 0 ]; then
                issues=()
                [ "$httponly" -eq 0 ] && issues+=("sin HttpOnly - vulnerable a XSS")
                [ "$secure" -eq 0 ] && issues+=("sin Secure - se envía sin cifrar")
                [ "$samesite" = "none" ] && [ "$secure" -eq 1 ] && [ "$httponly" -eq 1 ] && issues+=("SameSite=None - posible CSRF")
                
                VULNERABLE_COOKIES+=("  - $cookie_name [${issues[*]}]")
            fi
            
            echo "  - $cookie_name"
        done <<< "$COOKIE_HEADERS"
        
        # Mostrar cookies vulnerables si existen
        if [ ${#VULNERABLE_COOKIES[@]} -gt 0 ]; then
            echo
            echo "⚠️  Cookies con problemas de seguridad:"
            printf '%s\n' "${VULNERABLE_COOKIES[@]}"
        else
            echo
            echo "✅ Todas las cookies tienen configuración segura"
        fi
    else
        echo "  Ninguna"
    fi

    # WHOIS (solo si es dominio raíz)
    echo
    if [ "$TARGET" = "$ROOT_DOMAIN" ]; then
        if [ "${REGISTRAR:-N/A}" != "N/A" ]; then
            echo "El registro fue hecho por $REGISTRAR el ${CREATED:-N/A} y vence el ${EXPIRES:-N/A}"
            echo "Los name server(s) son: ${NAMESERVERS:-N/A}"
        else
            echo "Información WHOIS no disponible."
        fi
    fi

    echo
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
} > "$REPORT"
    echo -e "\n${C}📄 Reporte exportado: ${REPORT}${NC}"
fi

# Footer
echo -e "\n${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
