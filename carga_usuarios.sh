#!/bin/bash
# Script de carga de usuarios y datos de prueba para FIS-EPN
# Mejorado: UID automático, contraseña = UID, prueba GSSAPI para todos
# Debe ejecutarse DESPUÉS de instalar los servicios con RomeroE-Proyecto2.sh

if [ "$EUID" -ne 0 ]; then
  echo "Ejecutar como root"
  exit 1
fi

# Configuración (coincide con el script principal)
DOMAIN="fis.epn.edu.ec"
HOSTNAME="auth"
FQDN="${HOSTNAME}.${DOMAIN}"
REALM="FIS.EPN.EDU.EC"
BASE_DN="dc=fis,dc=epn,dc=edu,dc=ec"
LDAP_ADMIN_DN="cn=admin,${BASE_DN}"

echo "=========================================="
echo "  Carga de Usuarios y Grupos de Prueba   "
echo "=========================================="
echo ""

read -s -p "Ingrese contraseña LDAP admin (la misma usada en instalacion): " LDAP_PASSWORD
echo

# ----------------------------
# Contador global para UID
# ----------------------------
NEXT_UID=10001

# ----------------------------
# 1. Verificar/Crear estructura base LDAP
# ----------------------------
echo "[LDAP] Verificando estructura base..."

# Verificar si existe la OU people
if ! ldapsearch -x -b "ou=people,$BASE_DN" -s base "(objectClass=*)" dn 2>/dev/null | grep -q "dn:"; then
    echo "[LDAP] Creando OU people..."
    cat > /tmp/ou-people.ldif << EOF
dn: ou=people,$BASE_DN
objectClass: organizationalUnit
ou: people
EOF
    ldapadd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_PASSWORD" -f /tmp/ou-people.ldif 2>/dev/null
    rm -f /tmp/ou-people.ldif
fi

# Verificar si existe la OU groups
if ! ldapsearch -x -b "ou=groups,$BASE_DN" -s base "(objectClass=*)" dn 2>/dev/null | grep -q "dn:"; then
    echo "[LDAP] Creando OU groups..."
    cat > /tmp/ou-groups.ldif << EOF
dn: ou=groups,$BASE_DN
objectClass: organizationalUnit
ou: groups
EOF
    ldapadd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_PASSWORD" -f /tmp/ou-groups.ldif 2>/dev/null
    rm -f /tmp/ou-groups.ldif
fi

# ----------------------------
# 2. Crear Grupos LDAP (uno por uno)
# ----------------------------
echo "[LDAP] Creando grupos organizacionales..."

# Grupo estudiantes
cat > /tmp/grupo-estudiantes.ldif << EOF
dn: cn=estudiantes,ou=groups,$BASE_DN
objectClass: posixGroup
cn: estudiantes
gidNumber: 10000
description: Grupo de estudiantes FIS
EOF
ldapadd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_PASSWORD" -f /tmp/grupo-estudiantes.ldif 2>/dev/null && echo "  [OK] Grupo estudiantes creado" || echo "  [INFO] Grupo estudiantes ya existe"

# Grupo profesores
cat > /tmp/grupo-profesores.ldif << EOF
dn: cn=profesores,ou=groups,$BASE_DN
objectClass: posixGroup
cn: profesores
gidNumber: 10001
description: Grupo de profesores FIS
EOF
ldapadd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_PASSWORD" -f /tmp/grupo-profesores.ldif 2>/dev/null && echo "  [OK] Grupo profesores creado" || echo "  [INFO] Grupo profesores ya existe"

# Grupo admins
cat > /tmp/grupo-admins.ldif << EOF
dn: cn=admins,ou=groups,$BASE_DN
objectClass: posixGroup
cn: admins
gidNumber: 10002
description: Administradores del sistema
EOF
ldapadd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_PASSWORD" -f /tmp/grupo-admins.ldif 2>/dev/null && echo "  [OK] Grupo admins creado" || echo "  [INFO] Grupo admins ya existe"

rm -f /tmp/grupo-*.ldif

# ----------------------------
# 3. Crear usuarios
# ----------------------------
# Estructura de usuarios: uid,nombre,apellido,grupo
USUARIOS=(
    "jperez,Juan,Perez,estudiantes"
    "mloza,Maria,Loza,estudiantes"
    "rgomez,Roberto,Gomez,profesores"
    "adminfis,Admin,Sistema,admins"
)

crear_usuario() {
    local uid="$1"
    local nombre="$2"
    local apellido="$3"
    local grupo_nom="$4"
    local gid_num
    local uid_num="$NEXT_UID"
    
    # Incrementar para el proximo usuario
    NEXT_UID=$((NEXT_UID + 1))

    case "$grupo_nom" in
        estudiantes) gid_num=10000 ;;
        profesores)  gid_num=10001 ;;
        admins)      gid_num=10002 ;;
        *) gid_num=10099 ;;
    esac

    local pass="$uid"  # la password sera = uid

    echo "------------------------------------------------"
    echo "Procesando usuario: $uid ($nombre $apellido)"
    echo "  UID: $uid_num, GID: $gid_num ($grupo_nom)"

    # Generar hash de contraseña para LDAP
    local ldap_pass_hash
    ldap_pass_hash=$(slappasswd -s "$pass")

    # LDAP
    cat > "/tmp/user-$uid.ldif" << EOF
dn: uid=$uid,ou=people,$BASE_DN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: $uid
cn: $nombre $apellido
sn: $apellido
givenName: $nombre
displayName: $nombre $apellido
mail: $uid@$DOMAIN
userPassword: $ldap_pass_hash
loginShell: /bin/bash
uidNumber: $uid_num
gidNumber: $gid_num
homeDirectory: /home/$uid
description: Usuario del grupo $grupo_nom
EOF

    if ldapadd -x -D "$LDAP_ADMIN_DN" -w "$LDAP_PASSWORD" -f "/tmp/user-$uid.ldif" 2>/dev/null; then
        echo "  [OK] Usuario $uid creado en LDAP"
    else
        echo "  [INFO] Usuario $uid ya existe en LDAP"
    fi

    # Asignar a grupo
    cat > "/tmp/group-mod-$uid.ldif" << EOF
dn: cn=$grupo_nom,ou=groups,$BASE_DN
changetype: modify
add: memberUid
memberUid: $uid
EOF
    if ldapmodify -x -D "$LDAP_ADMIN_DN" -w "$LDAP_PASSWORD" -f "/tmp/group-mod-$uid.ldif" 2>/dev/null; then
        echo "  [OK] Usuario $uid agregado al grupo $grupo_nom"
    else
        echo "  [INFO] Usuario $uid ya es miembro del grupo $grupo_nom"
    fi

    # Kerberos
    kadmin.local -q "addprinc -pw $pass $uid@$REALM" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  [OK] Principal Kerberos $uid@$REALM creado"
    else
        echo "  [INFO] Principal Kerberos $uid@$REALM ya existe"
    fi

    # Limpieza
    rm -f "/tmp/user-$uid.ldif" "/tmp/group-mod-$uid.ldif"
}

# Crear todos los usuarios
for u in "${USUARIOS[@]}"; do
    IFS=',' read -r uid nombre apellido grupo <<< "$u"
    crear_usuario "$uid" "$nombre" "$apellido" "$grupo"
done

# ----------------------------
# 4. Prueba de GSSAPI
# ----------------------------
echo ""
echo "=========================================="
echo "  Prueba de Autenticacion GSSAPI         "
echo "=========================================="
echo ""

probar_gssapi() {
    local user=$1
    local pass=$1
    echo "Probando usuario: $user..."
    echo "$pass" | kinit "$user@$REALM" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  [OK] Kerberos Ticket obtenido"
        ldapwhoami -Y GSSAPI -H ldap://$FQDN 2>/dev/null
        kdestroy 2>/dev/null
    else
        echo "  [FAIL] No se pudo obtener ticket Kerberos"
    fi
    echo ""
}

# Iterar todos los usuarios
for u in "${USUARIOS[@]}"; do
    IFS=',' read -r uid _ _ _ <<< "$u"
    probar_gssapi "$uid"
done

# ----------------------------
# 5. Verificación de usuarios creados
# ----------------------------
echo "=========================================="
echo "  Verificacion de Usuarios en LDAP       "
echo "=========================================="
echo ""

echo "--- Estudiantes (gidNumber=10000) ---"
ldapsearch -x -b "ou=people,$BASE_DN" "(gidNumber=10000)" uid cn -LLL 2>/dev/null | grep -E "^dn:|^uid:|^cn:" || echo "  (ninguno)"
echo ""

echo "--- Profesores (gidNumber=10001) ---"
ldapsearch -x -b "ou=people,$BASE_DN" "(gidNumber=10001)" uid cn -LLL 2>/dev/null | grep -E "^dn:|^uid:|^cn:" || echo "  (ninguno)"
echo ""

echo "--- Administradores (gidNumber=10002) ---"
ldapsearch -x -b "ou=people,$BASE_DN" "(gidNumber=10002)" uid cn -LLL 2>/dev/null | grep -E "^dn:|^uid:|^cn:" || echo "  (ninguno)"
echo ""

echo "--- Miembros de grupos ---"
echo "Estudiantes:"
ldapsearch -x -b "cn=estudiantes,ou=groups,$BASE_DN" memberUid -LLL 2>/dev/null | grep memberUid || echo "  (ninguno)"
echo "Profesores:"
ldapsearch -x -b "cn=profesores,ou=groups,$BASE_DN" memberUid -LLL 2>/dev/null | grep memberUid || echo "  (ninguno)"
echo "Admins:"
ldapsearch -x -b "cn=admins,ou=groups,$BASE_DN" memberUid -LLL 2>/dev/null | grep memberUid || echo "  (ninguno)"
echo ""

echo "=========================================="
echo "  Carga completada                        "
echo "=========================================="
