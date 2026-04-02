# Revenant Hacking Framework

**Framework de Post-Explotación Modular para Grey Hack**

Revenant es un framework profesional de hacking construido sobre el motor **Nini**. Proporciona herramientas avanzadas para todas las fases del compromiso: reconocimiento, explotación, persistencia, escalada, exfiltración y gestión de botnet.

---

## 📋 Tabla de Contenido

- [Instalación](#instalación)
- [Arquitectura](#arquitectura)
- [Comandos del REPL](#comandos-del-repl)
- [Módulos Disponibles](#módulos-disponibles)
- [Guía Rápida de Uso](#guía-rápida-de-uso)
- [Sintaxis Nini](#sintaxis-nini)
- [Solución de Problemas](#solución-de-problemas)

---

## Instalación

### Requisitos Previos
- Grey Hack (versión reciente)
- Nini transpiler (incluido en `/Nini/`)

### Pasos

1. **Clonar el repositorio:**
```bash
git clone <url-del-repositorio>
cd GreyHack/Revenant
```

2. **Generar el bundle:**
```bash
cd /ruta/a/GreyHack
bun Nini/nini-bundler/bundler.js Revenant/main.nini Revenant/revenant_bundle.nini
```

3. **Compilar en Grey Hack:**
   - Copiar el contenido de `revenant_bundle.nini`
   - Pegarlo en un nuevo archivo `.gs` en Grey Hack
   - Compilar y ejecutar

### Estructura del Proyecto

```
Revenant/
├── commands/              # Comandos del REPL
│   ├── exploit.nini       # Comandos de explotación
│   ├── jump.nini          # Jumping entre sesiones
│   └── recon.nini         # Reconocimiento
├── core/                  # Núcleo del sistema
│   ├── kernel.nini        # Kernel principal (Buffer, Log, Clipboard)
│   └── shell.nini         # Sistema de comandos y Glasspool
├── lib/                   # Librerías
│   └── ui.nini            # Componentes de interfaz
├── modulos/               # Módulos especializados (13 módulos)
│   ├── asalto.nini        # Motor de explotación táctico
│   ├── botnet.nini        # Gestión de enjambre/botnet
│   ├── escalada.nini      # Auditoría de escalada
│   ├── espectro.nini      # Reconocimiento remoto
│   ├── exfil.nini         # Exfiltración de datos
│   ├── intel.nini         # Cosecha de secretos
│   ├── inyeccion.nini     # Auto-replicación
│   ├── lateral.nini       # Movimiento lateral
│   ├── limpieza.nini      # Limpieza de logs
│   ├── persistencia.nini  # Backdoors
│   ├── red.nini           # Descubrimiento de red
│   ├── ui.nini            # Interfaz adicional
│   └── vault.nini         # Almacenamiento cifrado
├── main.nini              # Punto de entrada
├── repl.nini              # REPL interactivo
├── revenant_bundle.nini   # Versión empaquetada
└── revenant.gs            # Código compilado
```

---

## Arquitectura

### Componentes Principales

| Componente | Descripción |
|------------|-------------|
| **main.nini** | Punto de entrada, inicializa el sistema |
| **repl.nini** | REPL interactivo tipo Metasploit |
| **kernel.nini** | Gestión de Buffer, Log, Clipboard y funciones core |
| **shell.nini** | Sistema de comandos y Glasspool (shells persistentes) |
| **ui.nini** | Componentes de interfaz (colores, menús, tablas) |

### Características Principales

1. **Glasspool**: Sistema de shells remotas persistentes en memoria
2. **Vault Cifrado**: Almacenamiento XOR de credenciales y vulnerabilidades
3. **Enjambre/Botnet**: Gestión de múltiples shells simultáneas
4. **Pivoting/Bounce**: Ataque a través de routers comprometidos
5. **Auto-inyección**: Replicación automática en targets
6. **Modo Ninja**: Limpieza automática de logs y rastros

---

## Comandos del REPL

### Comandos Básicos

| Comando | Alias | Descripción |
|---------|-------|-------------|
| `ayuda` | `h` | Muestra el panel de comandos |
| `sesiones` | `ss` | Ver sesiones activas |
| `buffer` | `buf` | Ver buffer de objetos |
| `clearbuffer` | - | Limpiar buffer |
| `aliases` | - | Ver aliases definidos |
| `alias` | - | Crear alias personalizado |
| `kernel` | - | Información del kernel |
| `salir` | `x`, `q` | Salir del sistema |

### Reconocimiento

| Comando | Alias | Descripción |
|---------|-------|-------------|
| `scan <ip>` | `sc` | Escanear puertos de un objetivo |
| `whois <ip>` | - | Consultar WHOIS |
| `red escanear` | `re` | Escanear red local |
| `red info` | `ri` | Mostrar mapa de red |

### Explotación

| Comando | Alias | Descripción |
|---------|-------|-------------|
| `hack <ip>` | `h` | Explotar objetivo |
| `asalto` | `a` | Motor de explotación táctico |
| `jump` | `j` | Jump de sesión entre nodos |

### Post-Explotación

| Comando | Alias | Descripción |
|---------|-------|-------------|
| `vault` | `v` | Ver credenciales almacenadas |
| `intel` | `i` | Saqueo de información |
| `persistencia` | - | Configurar backdoors |
| `escalada` | - | Auditoría de escalada |
| `exfil` | - | Menú de exfiltración |
| `inject` | `inj` | Auto-replicación en target |
| `limpiarlogs` | - | Limpiar logs del sistema |

### Ejemplos de Uso

```bash
# Escanear un objetivo
Revenant > scan 192.168.1.100

# Explotar un puerto vulnerable
Revenant > hack 192.168.1.100

# Ver sesiones activas
Revenant > sesiones

# Saltar a otro nodo
Revenant > jump

# Saquear información del target
Revenant > intel

# Ver credenciales almacenadas
Revenant > vault

# Escanear red local
Revenant > red escanear
```

---

## APIs de Red

Revenant proporciona funciones utilities para escaneo y reconocimiento de red.

### Escaneo con `.ping()`

El método `.ping()` verifica si una IP es alcanzable en la red local:

```nini
sh = get_shell
resultado = sh.ping("192.168.0.4")
// Retorna: "Ping successful" o "ip unreachable"
```

**⚠️ IMPORTANTE - Retorna un string, NO 1/null:**
- `.ping()` retorna **"Ping successful"** o **"ip unreachable"** (string)
- NO retorna 1 o null como otros métodos

**Helper `disponible(ip)`:**
Para no recordar el string exacto, usa la función helper `disponible()`:

```nini
// disponible(ip) retorna 1 si hay host, 0 si no
si disponible("192.168.0.4") == 1:
    info("Host alcanzable!")

tarea disponible(ip):
    si not ip: retornar 0
    resultado = get_shell().ping(ip)
    si resultado == "Ping successful": retornar 1
    retornar 0
```

**Ejemplo de escaneo de red:**

```nini
tarea escanear_red:
    sh = get_shell
    comp = sh.host_computer
    ip_local = comp.local_ip
    
    partes = ip_local.split(".")
    red = partes[0] + "." + partes[1] + "." + partes[2] + "."
    
    hosts = []
    para i en rango(1, 255):
        ip = red + str(i)
        // Usar disponible() - retorna 1 o 0
        si disponible(ip) == 1:
            hosts.push(ip)
            info("  + " + ip)
    
    retornar hosts
```

**Ejemplo de escaneo de red local (correcto):**

```nini
tarea escanear_red:
    sh = get_shell
    comp = sh.host_computer
    ip_local = comp.local_ip
    
    partes = ip_local.split(".")
    red = partes[0] + "." + partes[1] + "." + partes[2] + "."
    
    info("Escaneando " + red + "0/24...")
    hosts = []
    
    para i en rango(1, 255):
        ip = red + str(i)
        // Verificar string exacto "Ping successful"
        si sh.ping(ip) == "Ping successful":
            hosts.push(ip)
            info("  + " + ip)
    
    info("Encontrados: " + str(len(hosts)) + " hosts")
    retornar hosts
```

### Detectar IP Local

```nini
tarea es_ip_local(ip):
    comp = get_shell().host_computer
    local_ip = comp.local_ip
    
    partes_local = local_ip.split(".")
    partes_ip = ip.split(".")
    
    red_local = partes_local[0] + "." + partes_local[1] + "." + partes_local[2]
    red_ip = partes_ip[0] + "." + partes_ip[1] + "." + partes_ip[2]
    
    retornar red_local == red_ip
```

### API de Red Completa

| Función | Descripción |
|---------|-------------|
| `sh.ping(ip)` | Verificar si IP es alcanzable (retorna 1 o null) |
| `sh.connect_service(ip, port, user, pass)` | Conectar a servicio (retorna shell o null) |
| `typeof(obj) == "shell"` | Verificar tipo de objeto |
| `resultado.ping("127.0.0.1")` | Verificar que shell es usable |

---

## Módulos Disponibles

### Core Modules

| Módulo | Descripción |
|--------|-------------|
| `kernel.nini` | Kernel principal con Buffer, Log, Clipboard |
| `shell.nini` | Sistema de comandos y Glasspool |

### Security Modules

| Módulo | Descripción |
|--------|-------------|
| `asalto.nini` | Motor de explotación táctico con soporte Bounce |
| `botnet.nini` | Gestión de enjambre/botnet |
| `escalada.nini` | Auditoría de vectores de escalada (SetUID/Writeable) |
| `persistencia.nini` | Backdoors y persistencia |

### Recon Modules

| Módulo | Descripción |
|--------|-------------|
| `espectro.nini` | Reconocimiento remoto |
| `intel.nini` | Cosecha automatizada de secretos (Bank/Mail/Passwd) |
| `red.nini` | Descubrimiento y mapeo de red |

### Utility Modules

| Módulo | Descripción |
|--------|-------------|
| `exfil.nini` | Exfiltración de datos |
| `inyeccion.nini` | Auto-replicación y despliegue |
| `lateral.nini` | Movimiento lateral |
| `limpieza.nini` | Limpieza de logs |
| `vault.nini` | Persistencia cifrada XOR |

### UI Modules

| Módulo | Descripción |
|--------|-------------|
| `ui.nini` | Componentes de interfaz (lib) |
| `ui.nini` | Interfaz adicional (modulos) |

---

## Guía Rápida de Uso

### Flujo de Trabajo Típico

```bash
# 1. Iniciar Revenant
Revenant > 

# 2. Fijar objetivo
Revenant > objetivo 192.168.1.100

# 3. Escanear puertos
Revenant > scan 192.168.1.100

# 4. Explotar vulnerabilidad
Revenant > hack 192.168.1.100

# 5. Ver sesiones obtenidas
Revenant > sesiones

# 6. Saquear información
Revenant > intel

# 7. Escalar privilegios
Revenant > escalada

# 8. Configurar persistencia
Revenant > persistencia

# 9. Exfiltrar datos
Revenant > exfil

# 10. Limpiar logs
Revenant > limpiarlogs

# 11. Ver botín
Revenant > vault
```

### Gestión de Sesiones

```bash
# Ver todas las sesiones
Revenant > sesiones

# Saltar a otra sesión
Revenant > jump
# Seleccionar nodo del menú

# Ver objetos en buffer
Revenant > buffer
```

### Uso del Vault

El Vault almacena credenciales y vulnerabilidades de forma cifrada en `/var/revenant/vault.db`.

```bash
# Ver contenido del vault
Revenant > vault

# Las credenciales se guardan automáticamente al:
# - Obtener acceso por SSH
# - Encontrar Bank.txt, Mail.txt, etc.
# - Cada exploit exitoso
```

### Modo Ninja

Habilitar el modo ninja para limpieza automática de logs:

```nini
// En tu código Nini
modo ninja:
```

Esto añade automáticamente scripts de limpieza al final del código compilado.

---

## Sintaxis Nini

Nini es el lenguaje en el que está escrito Revenant. Se transpila a MiniScript.

### Estructuras de Control

```nini
// Condicionales
si condicion:
    accion
osi otra_condicion:
    accion
sino:
    accion

// One-liners
si condicion: accion

// Bucles
para x in coleccion:
    accion

recorrer coleccion como x:
    accion

mientras condicion:
    accion
```

### Operadores

| Operador | Descripción | Ejemplo |
|----------|-------------|---------|
| `>>` | Pipeline | `a >> b()` = `b(a)` |
| `\|:` | Ternario | `cond >> val_true \|: val_false` |
| `y` | AND lógico | `si activo y detectado:` |
| `o` | OR lógico | `si error o timeout:` |
| `no` | NOT lógico | `si no detectado:` |

### Ternarios

```nini
// Sintaxis: condición >> valor_si_verdadero |: valor_si_falso
resultado = x > 5 >> "mayor" |: "menor"
estado = objetivo == ip >> "ACTUAL" |: "DISPONIBLE"
```

### Funciones

```nini
// Declaración
tarea nombre_funcion:
    accion

tarea funcion_con_params(param1, param2):
    accion

// Funciones one-liner
tarea saludar(nombre): print("Hola " + nombre)
```

### Variables Globales

```nini
// Declarar variables globales
global mi_variable = "valor"
global contador = 0
```

### Macros Nativas

Nini inyecta automáticamente librerías cuando usas estas funciones:

| Función | Descripción |
|---------|-------------|
| `buscar_vulnerabilidad(ip, port)` | Escanea y encuentra vulnerabilidades |
| `inyectar(lib, val)` | Inyecta exploit en librería |
| `explotar(data, pass)` | Explota y obtiene shell |
| `crackear_diccionario(hash)` | Descifra hashes |
| `secuestrar_wifi(iface)` | Ataque WiFi automatizado |
| `buscar_recursivo(nombre)` | Busca archivos recursivamente |
| `instalar_persistencia(tipo, port)` | Instala backdoor |

---

## Solución de Problemas

### Error: "Range out of bounds"

**Problema:** `rango(0, len(array))` incluye un índice extra.

**Solución:** Usar `rango(0, len(array) - 1)` ya que `range()` es inclusivo.

```nini
// ❌ Incorrecto
para i en rango(0, len(nodos)):
    info(nodos[i])

// ✅ Correcto
para i en rango(0, len(nodos) - 1):
    info(nodos[i])
```

### Error: "Variable no encontrada en globals"

**Problema:** Variables no accesibles en diferentes scopes.

**Solución:** Declarar variables con `global` en el archivo que las necesita.

```nini
// En main.nini
global vault_data = {}
global modo_ninja = false

// En vault.nini (ya accede a vault_data)
vault_data["clave"] = "valor"
```

### Error: "Macro limpiar_logs no definida"

**Problema:** La macro no se reemplaza correctamente.

**Solución:** Asegurarse de que la función `limpiar_logs` esté definida antes de usarla.

### Error al compilar bundle

**Problema:** Errores al generar el bundle con el bundler.

**Solución:**
1. Verificar que Bun está instalado: `bun --version`
2. Ejecutar desde la raíz del proyecto: `cd /ruta/a/GreyHack`
3. Usar la ruta correcta: `bun Nini/nini-bundler/bundler.js Revenant/main.nini Revenant/revenant_bundle.nini`

---

## Desarrollo

### Agregar Nuevos Módulos

1. Crear archivo `.nini` en carpeta correspondiente
2. Importar en `main.nini` si es necesario
3. Registrar comandos en `shell.nini` si aplica
4. Regenerar bundle: `bun Nini/nini-bundler/bundler.js Revenant/main.nini Revenant/revenant_bundle.nini`

### Estructura de un Módulo

```nini
// mi_modulo.nini

// Funciones del módulo
tarea mi_funcion:
    // código
    retornar resultado

// Si necesita variables globales
global mi_modulo_data = {}
```

---

## Referencia Rápida

### Comandos Frecuentes

```
help/h       - Ayuda
ss           - Sesiones
buf          - Buffer
sc <ip>      - Scan
h <ip>       - Hack
jump/j       - Jump
v            - Vault
i            - Intel
a            - Asalto
re           - Red escanear
ri           - Red info
inj          - Inject
```

### Atajos de Teclado (en Grey Hack)

- `Ctrl+C` - Interrumpir comando
- `Tab` - Autocompletar (si disponible)
- `↑/↓` - Historial de comandos

---

**"No somos errores en el sistema. Somos el sistema recuperando su memoria."**

*Desarrollado sobre Nini Engine.*
