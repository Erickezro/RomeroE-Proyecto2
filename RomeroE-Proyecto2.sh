#!/bin/bash

# Proyecto: Servicio Integrado de Directorio y Autenticación para la FIS
# Autor: Erick Romero - (Facultad de Ingeniería de Sistemas - EPN)

if [ "$EUID" -ne 0 ]; then
  echo "Ejecutar como root"
  exit 1
fi

echo "Iniciando instalacion del servicio integrado FIS-EPN"

#---------------------------------
# Configuracion basica - FIS EPN
#---------------------------------

DOMAIN="fis.epn.edu.ec"
HOSTNAME="auth"

# Detectar IP e interfaz en automatico
IP_ADDRESS=$(ip -4 route get 1.1.1.1 | awk '{print $7; exit}')
NET_IFACE=$(ip -4 route get 1.1.1.1 | awk '{print $5; exit}')

if [ -z "$IP_ADDRESS" ]; then
  echo "ERROR: No se pudo detectar la IP del servidor"
  exit 1
fi

if networkctl status "$NET_IFACE" | grep -qi dhcp; then
  echo "ADVERTENCIA: La interfaz parece usar DHCP"
  echo "Se recomienda configurar IP estatica antes de continuar"
fi

echo "IP detectada automaticamente: $IP_ADDRESS"
echo "Interfaz detectada: $NET_IFACE"

# Realm Kerberos (SIEMPRE en mayusculas)
REALM="FIS.EPN.EDU.EC"

# Base DN para LDAP
BASE_DN="dc=fis,dc=epn,dc=edu,dc=ec"

# Usuario administrador LDAP
LDAP_ADMIN_DN="cn=admin,${BASE_DN}"

# ==========================================
# Credenciales
# ==========================================
read -s -p "Ingrese contraseña LDAP admin: " LDAP_PASSWORD
echo
read -s -p "Ingrese contraseña Kerberos: " KERBEROS_PASSWORD
echo

# Validar que no esten vacias
if [ -z "$LDAP_PASSWORD" ] || [ -z "$KERBEROS_PASSWORD" ]; then
    echo "Error: Las contraseñas no pueden estar vacias"
    exit 1
fi

# ==========================================
# Variables derivadas
# ==========================================

FQDN="${HOSTNAME}.${DOMAIN}"


echo "=========================================="
echo "  Instalacion de Servicios Integrados    "
echo "=========================================="
echo ""
echo "Configuracion:"
echo "  Dominio: $DOMAIN"
echo "  Hostname: $FQDN"
echo "  IP: $IP_ADDRESS"
echo ""

# ----------------------
# 1. PREPARAR SISTEMA
# ----------------------
echo ""
echo "[1/5] Preparando sistema..."

# Verificar conectividad a internet
if ! ping -c 1 8.8.8.8 &> /dev/null; then
    echo "ADVERTENCIA: No hay conexion a Internet. Algunos paquetes podrian no instalarse."
fi

apt update -qq
apt install -y -qq wget curl net-tools dnsutils

# Configurar hostname
hostnamectl set-hostname $FQDN

# Configurar /etc/hosts (preservar entradas existentes importantes)
cp /etc/hosts /etc/hosts.backup.$(date +%Y%m%d)
cat > /etc/hosts << EOF
127.0.0.1       localhost
127.0.1.1       $(hostname)
$IP_ADDRESS     $FQDN $HOSTNAME

# IPv6
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOF

echo "Sistema preparado"

# ------------------------------
# 2. INSTALAR Y CONFIGURAR DNS
# ------------------------------
echo ""
echo "[2/5] Instalando DNS..."

# Deshabilitar systemd-resolved que usa el puerto 53
echo "[DNS] Deshabilitando systemd-resolved..."
systemctl disable systemd-resolved 2>/dev/null
systemctl stop systemd-resolved 2>/dev/null

# Eliminar el stub listener en el puerto 53
if [ -f /etc/systemd/resolved.conf ]; then
    sed -i 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
    sed -i 's/DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
fi

# Remover el symlink de resolv.conf
rm -f /etc/resolv.conf

# Crear resolv.conf temporal
cat > /etc/resolv.conf << EOF
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF

DEBIAN_FRONTEND=noninteractive apt install -y -qq bind9 bind9-utils

cat > /etc/bind/named.conf.local << EOF
zone "$DOMAIN" {
    type master;
    file "/etc/bind/db.$DOMAIN";
};
EOF

# Archivo de zona
cat > /etc/bind/db.$DOMAIN << EOF
\$TTL    86400
@       IN      SOA     $FQDN. admin.$DOMAIN. (
                        2026011001 ; Serial
                        3600       ; Refresh
                        900        ; Retry
                        1209600    ; Expire
                        86400 )    ; Negative Cache TTL

@       IN      NS      $FQDN.
@       IN      A       $IP_ADDRESS
$HOSTNAME       IN      A       $IP_ADDRESS

; Kerberos
_kerberos._tcp  IN      SRV     0 100 88  $FQDN.
_kerberos._udp  IN      SRV     0 100 88  $FQDN.

; Kerberos admin
_kpasswd._tcp   IN      SRV     0 100 464 $FQDN.
_kpasswd._udp   IN      SRV     0 100 464 $FQDN.

; LDAP
_ldap._tcp      IN      SRV     0 100 389 $FQDN.
EOF

# Configurar opciones de BIND
cat > /etc/bind/named.conf.options << EOF
options {
    directory "/var/cache/bind";
    
    // Escuchar en todas las interfaces
    listen-on port 53 { 127.0.0.1; $IP_ADDRESS; any; };
    listen-on-v6 { none; };
    
    // Permitir queries desde redes locales
    allow-query { localhost; 127.0.0.0/8; 192.168.0.0/16; 10.0.0.0/8; };
    
    // Habilitar recursion
    recursion yes;
    allow-recursion { localhost; 127.0.0.0/8; 192.168.0.0/16; 10.0.0.0/8; };
    
    // DNSSEC
    dnssec-validation auto;
    
    // Forwarding para resolver nombres externos
    forwarders {
        8.8.8.8;
        8.8.4.4;
    };
};
EOF

# Verificaciones
echo "[DNS] Verificando configuracion..."
named-checkconf
if [ $? -ne 0 ]; then
    echo "ERROR: Configuracion de BIND invalida"
    exit 1
fi

named-checkzone ${DOMAIN} /etc/bind/db.${DOMAIN}
if [ $? -ne 0 ]; then
    echo "ERROR: Archivo de zona invalido"
    exit 1
fi

# Reiniciar servicio
echo "[DNS] Reiniciando BIND9..."
systemctl restart bind9
systemctl enable bind9

# Esperar a que BIND inicie
sleep 3

# Verificar que BIND esta corriendo
if ! systemctl is-active --quiet bind9; then
    echo "ERROR: BIND9 no se inicio correctamente"
    systemctl status bind9 --no-pager
    journalctl -u bind9 -n 50 --no-pager
    exit 1
fi

# Configurar resolv.conf para usar nuestro DNS
cat > /etc/resolv.conf << EOF
nameserver 127.0.0.1
search $DOMAIN
EOF

# Verificar que DNS funciona correctamente
echo "[DNS] Verificando resolucion..."
sleep 3
MAX_RETRIES=5
RETRY=0
while [ $RETRY -lt $MAX_RETRIES ]; do
    if dig @localhost $FQDN +short 2>/dev/null | grep -q "$IP_ADDRESS"; then
        break
    fi
    RETRY=$((RETRY + 1))
    echo "[DNS] Intento $RETRY de $MAX_RETRIES..."
    sleep 2
done

if [ $RETRY -eq $MAX_RETRIES ]; then
    echo "ERROR: DNS no esta resolviendo correctamente despues de $MAX_RETRIES intentos"
    echo "Verificar manualmente con: dig @localhost $FQDN"
    exit 1
fi

echo "[DNS] Configuracion finalizada correctamente"

# ------------------------------
# 3. INSTALAR Y CONFIGURAR NTP
# ------------------------------
echo ""
echo "[3/5] Instalando NTP (Chrony)..."

apt install -y -qq chrony

timedatectl set-timezone America/Guayaquil

cat > /etc/chrony/chrony.conf << EOF
pool 0.south-america.pool.ntp.org iburst
pool 1.south-america.pool.ntp.org iburst
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync

allow 127.0.0.1
allow 192.168.0.0/16
EOF

systemctl restart chrony
systemctl enable chrony

chronyc makestep
chronyc tracking

echo "[NTP] Configuracion finalizada correctamente"

# --------------------------------
# 4. INSTALAR Y CONFIGURAR LDAP
# --------------------------------
echo ""
echo "[4/5] Instalando LDAP (OpenLDAP)..."

DEBIAN_FRONTEND=noninteractive apt install -y -qq slapd ldap-utils libsasl2-modules-gssapi-mit

# Detener slapd para configuracion inicial
systemctl stop slapd

# Asegurar servicios LDAP
sed -i 's|^SLAPD_SERVICES=.*|SLAPD_SERVICES="ldap:/// ldapi:///"|' /etc/default/slapd

# Iniciar slapd
systemctl start slapd
sleep 2

LDAP_HASH=$(slappasswd -s "$LDAP_PASSWORD")

# Configurar la base de datos LDAP (MDB)
cat > /tmp/ldap-config.ldif << EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcSuffix
olcSuffix: $BASE_DN

dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: $LDAP_ADMIN_DN

dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcRootPW
olcRootPW: $LDAP_HASH
EOF

ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/ldap-config.ldif 2>/dev/null 

# Estructura del directorio 
cat > /tmp/ldap-base.ldif << EOF
dn: $BASE_DN
objectClass: top
objectClass: dcObject
objectClass: organization
o: Facultad de Ingenieria de Sistemas - EPN
dc: fis

dn: ou=people,$BASE_DN
objectClass: organizationalUnit
ou: people

dn: ou=groups,$BASE_DN
objectClass: organizationalUnit
ou: groups
EOF

ldapadd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_PASSWORD" -f /tmp/ldap-base.ldif 2>/dev/null

ldapsearch -x -b "$BASE_DN"
echo "[LDAP] Configuracion finalizada correctamente"

systemctl restart slapd
systemctl enable slapd

# -----------------------------------
# 5. INSTALAR Y CONFIGURAR KERBEROS
# -----------------------------------
echo ""
echo "[5/5] Instalando Kerberos..."

# Pre-configuracion para instalacion no interactiva
debconf-set-selections << EOF
krb5-config krb5-config/default_realm string $REALM
krb5-config krb5-config/kerberos_servers string $FQDN
krb5-config krb5-config/admin_server string $FQDN
EOF

# Instalar solo paquetes necesarios (sin krb5-kdc-ldap para simplificar)
DEBIAN_FRONTEND=noninteractive apt install -y -qq krb5-kdc krb5-admin-server

# Crear directorio de configuracion
mkdir -p /etc/krb5kdc

# Configuracion archivo krb5.conf (cliente y servidor)
cat > /etc/krb5.conf << EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    $REALM = {
        kdc = $FQDN
        admin_server = $FQDN
        default_domain = $DOMAIN
    }

[domain_realm]
    .$DOMAIN = $REALM
    $DOMAIN = $REALM

[logging]
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmin.log
    default = FILE:/var/log/krb5lib.log
EOF

# Configurar KDC con base de datos local
cat > /etc/krb5kdc/kdc.conf << EOF
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88

[realms]
    $REALM = {
        acl_file = /etc/krb5kdc/kadm5.acl
        dict_file = /usr/share/dict/words
        admin_keytab = /etc/krb5kdc/kadm5.keytab
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        master_key_type = aes256-cts-hmac-sha1-96
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
        default_principal_flags = +preauth
    }
EOF

# ACL para administradores
cat > /etc/krb5kdc/kadm5.acl << EOF
*/admin@$REALM *
EOF

chmod 600 /etc/krb5kdc/kadm5.acl

echo "[Kerberos] Creando base de datos..."

# Crear base de datos Kerberos con la contraseña dada
# Usar expect-like approach con printf
kdb5_util create -s -r $REALM << KDB_EOF
$KERBEROS_PASSWORD
$KERBEROS_PASSWORD
KDB_EOF

echo "[Kerberos] Base de datos creada"

# Crear principals
echo "[Kerberos] Creando principals..."

# Principal administrativo
kadmin.local -q "addprinc -pw $KERBEROS_PASSWORD admin/admin@$REALM" 2>/dev/null

# Principal del host
kadmin.local -q "addprinc -randkey host/$FQDN@$REALM" 2>/dev/null

# Principal LDAP 
kadmin.local -q "addprinc -randkey ldap/$FQDN@$REALM" 2>/dev/null

# Generar keytabs
kadmin.local -q "ktadd -k /etc/krb5.keytab host/$FQDN@$REALM" 2>/dev/null
kadmin.local -q "ktadd -k /etc/krb5kdc/kadm5.keytab kadmin/admin@$REALM kadmin/changepw@$REALM" 2>/dev/null

# Permisos seguros
chmod 600 /etc/krb5.keytab 2>/dev/null
chmod 600 /etc/krb5kdc/kadm5.keytab 2>/dev/null

echo "[Kerberos] Principals creados correctamente"

# Iniciar servicios
echo "[Kerberos] Iniciando servicios..."
systemctl restart krb5-kdc
systemctl restart krb5-admin-server
systemctl enable krb5-kdc
systemctl enable krb5-admin-server

# Esperar a que inicien
sleep 3

# Verificar que los servicios iniciaron correctamente
if ! systemctl is-active --quiet krb5-kdc; then
    echo "ERROR: krb5-kdc no se inicio correctamente"
    systemctl status krb5-kdc --no-pager
    journalctl -u krb5-kdc -n 20 --no-pager
    exit 1
fi

if ! systemctl is-active --quiet krb5-admin-server; then
    echo "ERROR: krb5-admin-server no se inicio correctamente"
    systemctl status krb5-admin-server --no-pager
    journalctl -u krb5-admin-server -n 20 --no-pager
    exit 1
fi

echo "[Kerberos] Servicios iniciados correctamente"


# ------------------------------
# 6. INTEGRACION SASL/GSSAPI
# ------------------------------
echo ""
echo "[6/6] Configurando integracion SASL/GSSAPI..."

# 1. Generar Keytab para LDAP
# Verificar si ya existe para no duplicar entradas innecesariamente
if [ ! -f /etc/ldap/ldap.keytab ]; then
    echo "[SASL] Generando keytab para servicio LDAP..."
    kadmin.local -q "ktadd -k /etc/ldap/ldap.keytab ldap/$FQDN@$REALM" 2>/dev/null
    chown openldap:openldap /etc/ldap/ldap.keytab
    chmod 640 /etc/ldap/ldap.keytab
else
    echo "[SASL] Keytab LDAP ya existe."
fi

# 2. Configurar entorno para slapd
echo "[SASL] Configurando variables de entorno LDAP..."
if ! grep -q "KRB5_KTNAME" /etc/default/slapd; then
    echo 'export KRB5_KTNAME=/etc/ldap/ldap.keytab' >> /etc/default/slapd
    echo "[SASL] Variable KRB5_KTNAME agregada."
else
    echo "[SASL] Variable KRB5_KTNAME ya existe, verificando formato..."
    # Asegurar que tenga export
    if ! grep -q "export KRB5_KTNAME=/etc/ldap/ldap.keytab" /etc/default/slapd; then
        sed -i '/KRB5_KTNAME/d' /etc/default/slapd
        echo 'export KRB5_KTNAME=/etc/ldap/ldap.keytab' >> /etc/default/slapd
        echo "[SASL] Variable KRB5_KTNAME actualizada con export."
    fi
fi

# Reiniciar para tomar cambios de entorno
systemctl restart slapd
sleep 2

# 3. Configurar mapeos SASL (olcAuthzRegexp)
echo "[SASL] Configurando mapeos SASL (olcSaslHost, olcSaslRealm, olcAuthzRegexp)..."
cat > /tmp/sasl-config.ldif << EOF
dn: cn=config
changetype: modify
add: olcSaslHost
olcSaslHost: $FQDN
-
add: olcSaslRealm
olcSaslRealm: $REALM
-
add: olcAuthzRegexp
olcAuthzRegexp: {0}uid=([^,]*),cn=$REALM,cn=gssapi,cn=auth uid=\$1,ou=people,$BASE_DN
olcAuthzRegexp: {1}uid=host/([^,]*).$DOMAIN,cn=$REALM,cn=gssapi,cn=auth cn=\$1,ou=hosts,$BASE_DN
EOF

ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/sasl-config.ldif 2>&1 | tee /tmp/sasl-config.log
if [ $? -eq 0 ]; then
    echo "[SASL] Configuracion SASL aplicada correctamente."
else
    echo "[SASL] Nota: Error al aplicar configuracion (puede ser normal si ya existe)."
    # Intentar con replace si add fallo
    echo "[SASL] Intentando actualizar configuracion existente..."
    cat > /tmp/sasl-config-replace.ldif << EOF
dn: cn=config
changetype: modify
replace: olcSaslHost
olcSaslHost: $FQDN
-
replace: olcSaslRealm
olcSaslRealm: $REALM
-
replace: olcAuthzRegexp
olcAuthzRegexp: {0}uid=([^,]*),cn=$REALM,cn=gssapi,cn=auth uid=\$1,ou=people,$BASE_DN
olcAuthzRegexp: {1}uid=host/([^,]*).$DOMAIN,cn=$REALM,cn=gssapi,cn=auth cn=\$1,ou=hosts,$BASE_DN
EOF
    ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/sasl-config-replace.ldif 2>&1
    rm -f /tmp/sasl-config-replace.ldif
fi

rm -f /tmp/sasl-config.ldif /tmp/sasl-config.log

# Reiniciar slapd nuevamente para aplicar cambios SASL
echo "[SASL] Reiniciando slapd para aplicar configuracion SASL..."
systemctl restart slapd
sleep 3

if systemctl is-active --quiet slapd; then
    echo "[SASL] Servicio slapd reiniciado correctamente."
else
    echo "ERROR: slapd no se inicio correctamente despues de configurar SASL."
    systemctl status slapd --no-pager
    exit 1
fi

echo "[SASL] Integracion configurada."

# Verificar mecanismos SASL soportados
echo "[SASL] Verificando mecanismos SASL soportados..."
ldapsearch -x -H ldap://$FQDN -b "" -s base -LLL supportedSASLMechanisms 2>/dev/null | grep -i gssapi
if [ $? -eq 0 ]; then
    echo "[SASL] GSSAPI esta disponible."
else
    echo "[SASL] ADVERTENCIA: GSSAPI no aparece en mecanismos soportados."
fi

#-----------------------------
# VERIFICACIoN FINAL
#-----------------------------
echo ""
echo "=========================================="
echo "  VERIFICACION DE SERVICIOS              "
echo "=========================================="

# DNS
echo ""
echo "[DNS] Resolviendo $FQDN:"
dig @localhost $FQDN +short

# NTP
echo ""
echo "[NTP] Estado de sincronizacion:"
chronyc tracking | head -5

# LDAP
echo ""
echo "[LDAP] Estructura del directorio:"
ldapsearch -x -b "$BASE_DN" -LLL dn 2>/dev/null

# Kerberos
echo ""
echo "[Kerberos] Listando principals:"
kadmin.local -q "listprincs" 2>/dev/null | head -10

echo ""
echo "============================================"
echo "  INSTALACION DE INFRAESTRUCTURA COMPLETADA "
echo "============================================"
echo ""
echo "Siguientes pasos: ejecute 'carga_usuarios.sh' para crear usuarios."
echo "Credenciales: LDAP=$LDAP_ADMIN_DN, Kerberos=admin/admin@$REALM"
echo "Comandos utiles: kinit, klist, kdestroy, ldapsearch -x -b '$BASE_DN'"
echo ""
echo "Servicios activos:"
systemctl is-active bind9 && echo "  DNS (BIND9): activo" || echo "  DNS (BIND9): inactivo"
systemctl is-active chrony && echo "  NTP (Chrony): activo" || echo "  NTP (Chrony): inactivo"
systemctl is-active slapd && echo "  LDAP (OpenLDAP): activo" || echo "  LDAP (OpenLDAP): inactivo"
systemctl is-active krb5-kdc && echo "  Kerberos KDC: activo" || echo "  Kerberos KDC: inactivo"
systemctl is-active krb5-admin-server && echo "  Kerberos Admin: activo" || echo "  Kerberos Admin: inactivo"