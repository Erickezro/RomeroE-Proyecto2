# Servicio Integrado de Directorio y Autenticación para la FIS

**Autor:** Erick Romero  
**Institución:** Facultad de Ingeniería de Sistemas - Escuela Politécnica Nacional  
**Proyecto:** Sistema Integrado de Directorio y Autenticación

---

## 📋 Descripción del Proyecto

Este proyecto implementa un **sistema integrado de directorio y autenticación** para la Facultad de Ingeniería de Sistemas (FIS) de la EPN, combinando los servicios de:

- **DNS (BIND9)** - Resolución de nombres y registros SRV para descubrimiento de servicios
- **NTP (Chrony)** - Sincronización de tiempo precisa (crítica para Kerberos)
- **LDAP (OpenLDAP)** - Directorio centralizado de usuarios y grupos
- **Kerberos (MIT Kerberos)** - Autenticación segura mediante tickets
- **SASL/GSSAPI** - Integración entre Kerberos y LDAP para autenticación transparente

El sistema permite autenticación única (Single Sign-On) donde los usuarios se autentican una vez con Kerberos y pueden acceder a servicios LDAP sin volver a ingresar credenciales.

---

## 🏗️ Arquitectura del Sistema

```
┌─────────────────────────────────────────────────┐
│            Usuario Final (Cliente)              │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│              DNS (BIND9)                        │
│  - Resolución de nombres                        │
│  - Registros SRV (_kerberos, _ldap)             │
└──────────────────┬──────────────────────────────┘
                   │
        ┌──────────┴──────────┐
        ▼                     ▼
┌─────────────────┐    ┌───────────────────┐
│  NTP (Chrony)   │    │ Kerberos (KDC)    │
│  - Sincroniza-  │    │ - Autenticación   │
│    ción tiempo  │    │ - Emisión tickets │
└─────────────────┘    └────────┬──────────┘
                                │
                                │ GSSAPI/SASL
                                ▼
                        ┌─────────────────┐
                        │  LDAP (OpenLDAP)│
                        │  - Directorio   │
                        │  - Usuarios     │
                        │  - Grupos       │
                        └─────────────────┘
```

### Componentes Principales

1. **DNS (BIND9)**
   - Dominio: `fis.epn.edu.ec`
   - Hostname: `auth.fis.epn.edu.ec`
   - Registros SRV para autodescubrimiento de Kerberos y LDAP

2. **NTP (Chrony)**
   - Sincronización con servidores de América del Sur
   - Esencial para el correcto funcionamiento de Kerberos (tolerancia de 5 minutos)

3. **LDAP (OpenLDAP)**
   - Base DN: `dc=fis,dc=epn,dc=edu,dc=ec`
   - Estructura organizacional con OUs: `people`, `groups`
   - Grupos: estudiantes (GID 10000), profesores (GID 10001), admins (GID 10002)

4. **Kerberos (MIT KDC)**
   - Realm: `FIS.EPN.EDU.EC`
   - Autenticación basada en tickets
   - Integración con LDAP mediante GSSAPI

5. **SASL/GSSAPI**
   - Capa de autenticación entre Kerberos y LDAP
   - Mapeo automático de identidades Kerberos → LDAP DN
   - Cifrado de capa de datos (SSF: 256-bit)

---

## 🚀 Instalación

### Requisitos Previos

- **Sistema Operativo:** Ubuntu 20.04/22.04 LTS
- **Recursos mínimos:** 2GB RAM, 20GB disco, 1 CPU
- **Red:** IP estática configurada (recomendado)
- **DNS:** El servidor debe tener configurado DNS apuntando a su propia IP y a un DNS público (ej. 8.8.8.8) para resolver nombres externos durante la instalación
- **Privilegios:** Acceso root
- **Conectividad:** Acceso a internet para descargar paquetes

### 🌐Configuración de Red Previa (Importante)

Antes de ejecutar los scripts, asegúrate de tener configurada la red correctamente:

---
**✅ Opción recomendada: Configuración mediante interfaz gráfica (GUI)**

1. Abre **Settings (Configuración)**

2. Ve a Network

3. Selecciona tu interfaz (Wired / Ethernet)

4. Haz clic en ⚙️ Settings

5. En la pestaña IPv4:
- Method: `Manual`
- Address: `192.168.1.10`
- Netmask: `255.255.255.0`
- Gateway: `192.168.1.1`
6. En DNS agrega: `192.168.1.10,8.8.8.8,8.8.4.4`

7. Guarda los cambios y reinicia la conexión de red
---
**⚙️ Opción alternativa: Configuración manual por consola (avanzado)**

**⚠️ Usa esta opción solo si no deseas usar la interfaz gráfica**

#### 1. Configurar IP Estática

```bash
# Editar configuración
sudo nano /etc/netplan/00-installer-config.yaml
```

```yaml
network:
  version: 2
  ethernets:
    eth0:  # o el nombre de tu interfaz
      dhcp4: no
      addresses:
        - 192.168.1.100/24  # Tu IP estática
      gateway4: 192.168.1.1  # Tu gateway
      nameservers:
        addresses:
          - 192.168.1.100    # La IP de este servidor
          - 8.8.8.8          # DNS público de Google
          - 8.8.4.4          # DNS público secundario
```

```bash
# Aplicar cambios
sudo netplan apply
```

#### 2. Configurar DNS Temporal

Antes de ejecutar el script, configura DNS para poder descargar paquetes:

```bash
# Editar resolv.conf
sudo nano /etc/resolv.conf
```

```
nameserver 8.8.8.8
nameserver 8.8.4.4
```

**Nota:** El script `RomeroE-Proyecto2.sh` reconfigurará automáticamente el DNS para que apunte a 127.0.0.1 (el servidor DNS local que instalará).

#### 3. Verificar Conectividad

```bash
# Verificar IP configurada
ip addr show

# Verificar gateway
ip route

# Verificar DNS
cat /etc/resolv.conf

# Probar conectividad a internet
ping -c 4 8.8.8.8
ping -c 4 google.com
```
---
### Paso 1: Preparar el sistema

```bash
# Clonar el repositorio
git clone https://github.com/
cd Proyecto-Servicio-Directorio

# Dar permisos de ejecución a los scripts
chmod +x RomeroE-Proyecto2.sh
chmod +x carga_usuarios.sh
```

### Paso 2: Ejecutar instalación principal

```bash
# Ejecutar como root
sudo ./RomeroE-Proyecto2.sh
```

El script solicitará:
- **Contraseña LDAP admin:** Para administrar el directorio LDAP
- **Contraseña Kerberos:** Para la base de datos KDC

**Nota:** Estas contraseñas se usarán más adelante, guárdalas en un lugar seguro.

El script automáticamente:
1. ✅ Configura hostname y /etc/hosts
2. ✅ Instala y configura DNS (BIND9)
3. ✅ Instala y configura NTP (Chrony)
4. ✅ Instala y configura LDAP (OpenLDAP)
5. ✅ Instala y configura Kerberos (KDC)
6. ✅ Configura integración SASL/GSSAPI
7. ✅ Verifica que todos los servicios estén funcionando

**Tiempo estimado:** 5-10 minutos

### Paso 3: Cargar usuarios de prueba

```bash
# Ejecutar como root
sudo ./carga_usuarios.sh
```

El script solicitará la contraseña LDAP admin (la misma del paso anterior).

Creará automáticamente:
- **Grupos:** estudiantes, profesores, admins
- **Usuarios de prueba:**
  - `jperez` (estudiante) - contraseña: `jperez`
  - `mloza` (estudiante) - contraseña: `mloza`
  - `rgomez` (profesor) - contraseña: `rgomez`
  - `adminfis` (admin) - contraseña: `adminfis`

Al finalizar, ejecutará pruebas de autenticación GSSAPI para cada usuario.

---

## 🔧 Configuración

### Estructura del Directorio LDAP

```
dc=fis,dc=epn,dc=edu,dc=ec
├── ou=people
│   ├── uid=jperez (estudiante)
│   ├── uid=mloza (estudiante)
│   ├── uid=rgomez (profesor)
│   └── uid=adminfis (admin)
└── ou=groups
    ├── cn=estudiantes (gidNumber: 10000)
    ├── cn=profesores (gidNumber: 10001)
    └── cn=admins (gidNumber: 10002)
```

### Archivos de Configuración Importantes

Los scripts crean y configuran automáticamente todos los archivos necesarios.

| Servicio | Archivo de Configuración | Descripción |
|----------|-------------------------|-------------|
| DNS | `/etc/bind/db.fis.epn.edu.ec` | Zona DNS principal |
| DNS | `/etc/bind/named.conf.local` | Configuración de zonas |
| NTP | `/etc/chrony/chrony.conf` | Servidores NTP |
| LDAP | `/etc/ldap/slapd.d/cn=config` | Configuración dinámica LDAP |
| LDAP | `/etc/default/slapd` | Variables de entorno (KRB5_KTNAME) |
| Kerberos | `/etc/krb5.conf` | Configuración cliente Kerberos |
| Kerberos | `/etc/krb5kdc/kdc.conf` | Configuración KDC |
| Keytabs | `/etc/ldap/ldap.keytab` | Keytab para servicio LDAP |

**Nota:** Estos archivos se generan automáticamente durante la instalación y residen en el servidor, no en este repositorio.

---

## 📖 Uso del Sistema

### Autenticación con Kerberos

```bash
# Obtener ticket de Kerberos
kinit jperez
# Ingresa la contraseña: jperez

# Verificar ticket obtenido
klist

# Destruir ticket (logout)
kdestroy
```

### Consultas LDAP

#### Autenticación tradicional (con contraseña)

```bash
# Buscar todos los usuarios
ldapsearch -x -b "dc=fis,dc=epn,dc=edu,dc=ec" -LLL "(objectClass=posixAccount)"

# Buscar un usuario específico
ldapsearch -x -b "dc=fis,dc=epn,dc=edu,dc=ec" "(uid=jperez)"

# Ver grupos
ldapsearch -x -b "ou=groups,dc=fis,dc=epn,dc=edu,dc=ec" -LLL
```

#### Autenticación con GSSAPI (usando ticket Kerberos)

```bash
# Primero obtener ticket
kinit jperez

# Consultar LDAP con GSSAPI (sin contraseña)
ldapsearch -Y GSSAPI -H ldap://auth.fis.epn.edu.ec \
  -b "dc=fis,dc=epn,dc=edu,dc=ec" "(uid=jperez)"

# Verificar identidad actual
ldapwhoami -Y GSSAPI -H ldap://auth.fis.epn.edu.ec
# Resultado: dn:uid=jperez,ou=people,dc=fis,dc=epn,dc=edu,dc=ec
```

### Identificar Tipo de Usuario

#### Por GID (Grupo Primario)

```bash
# Estudiantes (gidNumber=10000)
ldapsearch -x -b "dc=fis,dc=epn,dc=edu,dc=ec" \
  "(gidNumber=10000)" uid cn mail

# Profesores (gidNumber=10001)
ldapsearch -x -b "dc=fis,dc=epn,dc=edu,dc=ec" \
  "(gidNumber=10001)" uid cn mail

# Administradores (gidNumber=10002)
ldapsearch -x -b "dc=fis,dc=epn,dc=edu,dc=ec" \
  "(gidNumber=10002)" uid cn mail
```

#### Consultar usuario específico

```bash
ldapsearch -x -b "dc=fis,dc=epn,dc=edu,dc=ec" \
  "(uid=jperez)" gidNumber description
```

#### Ver miembros de un grupo

```bash
# Miembros del grupo estudiantes
ldapsearch -x -b "cn=estudiantes,ou=groups,dc=fis,dc=epn,dc=edu,dc=ec" memberUid
```

### Administración de Usuarios

#### Crear nuevo usuario (ejemplo)

```bash
# 1. Crear principal Kerberos
sudo kadmin.local -q "addprinc -pw password nuevousuario@FIS.EPN.EDU.EC"

# 2. Crear entrada LDAP
# Crear archivo nuevousuario.ldif con el contenido apropiado
sudo ldapadd -x -D "cn=admin,dc=fis,dc=epn,dc=edu,dc=ec" -W -f nuevousuario.ldif

# 3. Agregar a grupo
# Crear archivo agregar-grupo.ldif
sudo ldapmodify -x -D "cn=admin,dc=fis,dc=epn,dc=edu,dc=ec" -W -f agregar-grupo.ldif
```

#### Cambiar contraseña de usuario

```bash
# Kerberos
sudo kadmin.local -q "cpw jperez@FIS.EPN.EDU.EC"

# LDAP
sudo ldappasswd -x -D "cn=admin,dc=fis,dc=epn,dc=edu,dc=ec" -W \
  -S "uid=jperez,ou=people,dc=fis,dc=epn,dc=edu,dc=ec"
```

#### Eliminar usuario

```bash
# Kerberos
sudo kadmin.local -q "delprinc -force jperez@FIS.EPN.EDU.EC"

# LDAP
sudo ldapdelete -x -D "cn=admin,dc=fis,dc=epn,dc=edu,dc=ec" -W \
  "uid=jperez,ou=people,dc=fis,dc=epn,dc=edu,dc=ec"
```

---

## 🔍 Verificación y Troubleshooting

### Verificar estado de servicios

```bash
# Ver estado de todos los servicios
systemctl status bind9
systemctl status chrony
systemctl status slapd
systemctl status krb5-kdc
systemctl status krb5-admin-server
```

### Verificar DNS

```bash
# Resolver FQDN
dig @localhost auth.fis.epn.edu.ec

# Verificar registros SRV de Kerberos
dig @localhost _kerberos._tcp.fis.epn.edu.ec SRV

# Verificar registros SRV de LDAP
dig @localhost _ldap._tcp.fis.epn.edu.ec SRV
```

### Verificar NTP

```bash
# Estado de sincronización
chronyc tracking

# Fuentes NTP
chronyc sources
```

### Verificar LDAP

```bash
# Verificar mecanismos SASL soportados
ldapsearch -x -H ldap://auth.fis.epn.edu.ec \
  -b "" -s base -LLL supportedSASLMechanisms

# Debe mostrar: supportedSASLMechanisms: GSSAPI
```

### Verificar Kerberos

```bash
# Listar principals
sudo kadmin.local -q "listprincs"

# Verificar keytab del host
sudo klist -k /etc/krb5.keytab

# Verificar keytab de LDAP
sudo klist -k /etc/ldap/ldap.keytab
```

### Verificar integración SASL/GSSAPI

```bash
# Ver configuración SASL en LDAP
sudo ldapsearch -Y EXTERNAL -H ldapi:/// \
  -b cn=config -LLL olcSaslHost olcSaslRealm olcAuthzRegexp

# Probar autenticación GSSAPI
kinit jperez
ldapwhoami -Y GSSAPI -H ldap://auth.fis.epn.edu.ec
```

### Logs útiles para diagnóstico

```bash
# Logs de LDAP
sudo journalctl -u slapd -n 50

# Logs de Kerberos KDC
sudo tail -f /var/log/krb5kdc.log

# Logs de DNS
sudo journalctl -u bind9 -n 50

# Logs de NTP
sudo journalctl -u chrony -n 50
```

### Problemas Comunes

#### Error: "Clock skew too great" en Kerberos
**Causa:** Diferencia de tiempo mayor a 5 minutos entre cliente y servidor  
**Solución:**
```bash
sudo chronyc makestep
sudo systemctl restart krb5-kdc
```

#### Error: GSSAPI no disponible en LDAP
**Causa:** Keytab no configurado o variable KRB5_KTNAME no establecida  
**Solución:**
```bash
# Verificar keytab
sudo ls -l /etc/ldap/ldap.keytab
sudo klist -k /etc/ldap/ldap.keytab

# Verificar variable en slapd
grep KRB5_KTNAME /etc/default/slapd

# Reiniciar LDAP
sudo systemctl restart slapd
```

#### Error: DNS no resuelve
**Causa:** systemd-resolved interfiriendo con BIND9  
**Solución:**
```bash
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
sudo rm /etc/resolv.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
sudo systemctl restart bind9
```

---

## 🔐 Seguridad

### Consideraciones de Seguridad

1. **Contraseñas:**
   - Las contraseñas de prueba son simples (iguales al username)
   - En un entorno real, usar contraseñas fuertes y políticas de complejidad
   - Considerar integración con `cracklib` para validación de contraseñas

2. **Red:**
   - El sistema está configurado para aceptar conexiones de redes locales
   - En un entorno real, restringir acceso por firewall (iptables/nftables)
   - Considerar cifrado TLS para LDAP (puerto 636)

3. **Keytabs:**
   - Los keytabs son archivos sensibles con permisos restringidos
   - Mantener respaldos seguros de `/etc/krb5.keytab` y `/etc/ldap/ldap.keytab`

4. **Backups:**
   - Respaldar regularmente la base de datos LDAP (`/var/lib/ldap`)
   - Respaldar la base de datos Kerberos (`/var/lib/krb5kdc`)

### Mejoras de Seguridad Recomendadas

```bash
# Configurar firewall básico
sudo ufw allow 53/tcp    # DNS
sudo ufw allow 53/udp    # DNS
sudo ufw allow 88/tcp    # Kerberos
sudo ufw allow 88/udp    # Kerberos
sudo ufw allow 389/tcp   # LDAP
sudo ufw allow 464/tcp   # Kerberos kpasswd
sudo ufw allow 464/udp   # Kerberos kpasswd
sudo ufw allow 749/tcp   # Kerberos kadmin
sudo ufw enable
```

---

## 📚 Referencias

- [OpenLDAP Documentation](https://www.openldap.org/doc/)
- [MIT Kerberos Documentation](https://web.mit.edu/kerberos/krb5-latest/doc/)
- [BIND9 Documentation](https://bind9.readthedocs.io/)
- [Chrony Documentation](https://chrony.tuxfamily.org/documentation.html)
- [SASL/GSSAPI Integration](https://www.openldap.org/doc/admin24/sasl.html)

---

## 📝 Licencia

Este proyecto es un prototipo académico desarrollado para la Facultad de Ingeniería de Sistemas - EPN.

---

## 👤 Autor

**Erick Romero**  
Facultad de Ingeniería de Sistemas  
Escuela Politécnica Nacional
