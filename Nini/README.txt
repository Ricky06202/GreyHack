Wraith OS v4.0 - Framework Modular para GreyHack
==============================================

Archivos:
- wraith_main.src: Ejecutable principal
- install.src: Instalador automático
- wraith_*.src: Módulos del sistema
- README.txt: Esta documentación

Instalación automática (recomendado):
1. Copiar todos los archivos .src a Grey Hack
2. Ejecutar: build install.src /bin/install && install
3. El instalador creará /lib/wraith/ y copiará los módulos
4. Compilará wraith a /bin/wraith

Instalación manual:
1. mkdir /lib/wraith
2. Copiar wraith_*.src a /lib/wraith/
3. build wraith_main.src /bin/wraith
4. Ejecutar: wraith [target_ip]

Características:
- import_code() para cargar módulos .src
- Persistencia en .wraith_vault
- Tablas sin colores en separadores
- HUD de ruta: LOCAL -> Target
- Escaneo de red LAN/WAN automático
- Extracción de Bank.txt y Mail.txt
- Gestión de logs quirúrgica
- Multi-hop Bouncing para pivoting
- Interfaz neón estilo hacker (solo ASCII)
- Colores hexadecimales compatibles