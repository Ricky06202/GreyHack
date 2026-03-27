# Nini - Documentación Oficial (Auto-Hacker & OS Framework)

Nini ha evolucionado de un simple transpilador a un **Lanzador de Exploits y Sistema Operativo de Red Team** (Nini-Wraith OS) super-vitaminado para Grey Hack. Convierte eficientemente código escrito en un espanglish minimalista (estilo Python) a **MiniScript** nativo, inyectando abstracciones automáticas para saltarse el 90% del código aburrido.

## Filosofía del Lenguaje
- **Pipelines Rápidos:** Operadores orientados al flujo (`>>`).
- **Pythonic:** Nini **descartó las llaves `{ }`**, es 100% basado en indentaciones limpias.
- **Inyección Bajo Demanda:** Nini inyecta librerías (`crypto.so`, `metaxploit.so`) o subrutinas complejas al tope de tu archivo compilado `.gs` **solo** si usas una de las APIs maestras.

---

## 1. El Contexto Global y Sintaxis Nativa

Nini rastrea el estado del servidor a atacar para ahorrarte variables estáticas:
```nini
target = "192.168.1.10"
// Macros nativas asumirán siempre este target_ip si lo omites.
```

## 2. Estructuras de Control (Zero-Braces)

### Condicionales
```nini
si puerto == 22:
    info("SSH Encontrado")
osi puerto == 21:
    info("FTP Encontrado")
sino:
    info("Puerto misterioso")
```

### Bucles e Iteradores (Sintaxis Dual)
Nini soporta tanto la sintaxis clásica como una más descriptiva:

```nini
// Sintaxis Descriptiva (Recomendada para Revenant)
recorrer red_local como ip:
    escanear(ip)

// Sintaxis Clásica
para ip en red_local:
    escanear(ip)

para intento en rango(0, 10):
    info("Fuzzing " + intento)

// Bucle WHILE y Bucle Infinito
mientras atacando == verdadero:
    esperar(1)

siempre:
    info("Ping constante...")
```

### Operadores Lógicos en Español
Ya no necesitas usar `and/or/not` de GreyScript. Nini los traduce por ti:
- `si activo y no detectado o forzar:` -> `if (activo and not detectado or forzar) then`

### Controles y Try-Catch Puros
- `salir` -> Corta un bucle inmediatamente (`break`).
- `siguiente` -> Salta a la siguiente iteración (`continue`).

```nini
intentar:
    explotar(puerto)
excepto:
    error("Fallo la rutina... salvando el sistema sin crasheo.")
```

## 3. Pipeline de Múltiples Tareas (`>>`) y Arrays (`...`)

Pasa llamadas fluidamente de una función a otra.
```nini
obtener_target >> escanear >> buscar_vulnerabilidad >> explotar
```

**Operador Spread (Listas dinámicas):** Extiende arreglos con la magia de 3 puntos.
```nini
info_total = [ ...datos_pc1, ...datos_pc2, "extra_info" ]
```

## 4. GreyScript Supercharged: Asincronía
Nini emula procesos Multihilo (Background Workers) en un juego Single-Thread.
```nini
ejecutar_en_segundo_plano:
    mientras verdadero:
        esperar(10)
        limpiar
```
> **¿Cómo funciona?** Nini empaquetará el bloque `en_segundo_plano` en un archivo binario `.gs` huérfano y lo lanzará en tu terminal con `host.launch()`, eliminando el rastro luego, dejándolo en RAM ejecutándose para siempre sin interrumpir tu hackeo principal.

## 5. Inteligencia de Enjambre (Swarm)
Guarda arrays de shells en el hiper-espacio y ordénales ejecutar un ataque sincronizado o una limpieza general.
```nini
enjambre.añadir(shell_victima)
enjambre.ejecutar_todo("limpiar")
```

---

## 6. Nini-Wraith OS & Auto-Hacker (Las APIs Definitivas)

Nini detectará qué función súper-avanzada vas a usar y escribirá de 20 a 50 líneas de programación orientada a punteros, diccionarios y memoria detrás de escena, condensándolo para ti en solo 1 palabra:

### Exploit Builder & Memory Fuzzer
Deja de usar bucles `for mem in` confusos. 
- `buscar_vulnerabilidad(ip, port)` -> Arroja la primera estructura `mem` válida.
- `inyectar(libreria, "val")` -> Escanea un objeto MetaLib hasta encontrar la variable correcta y revienta la memoria de la librería. Devuelve un resultado real (Shell o Computer).
- `explotar(data, "pass") >> obtener_shell` -> Recrea el clásico proceso de obtener root usando `.overflow()`.

### Criptografía (Diccionarios y WiFi)
- `claves = crackear_diccionario(fake_hash_string)` -> Le tiras un string copiado con saltos de línea de `#cat /etc/shadow` y él separa todo limpiamente, itera un descifrado con `crypto.decipher()` y crea tu Diccionario Asociativo.
- `clave_wpa = secuestrar_wifi("wlan0")` -> Invoca a `airmon`, escoge tu primer BSSID de señal alta, configura ACKs con `aireplay` e inyecta la recolección hacia un `aircrack` fantasma. Retorna el String.

### Utilities (Búsquedas Filesystem & Persistencia)
- `mi_archivo = buscar_recursivo("Bank.txt")` -> Escribe un DFS Stack Loop veloz (recursividad simulada para no crashear variables en el Heap de tu PC) que busca por el disco y retorna el objeto.
- `instalar_persistencia("oculto", 8080)` -> Automatización de troyano: infecta el registro de inicio usando cron-jobs, ocultando al sistema una tarea que revive si la víctima reinicia el servidor.

### La Interfaz Estilizada `Nini-UI`
- **`ip = pedir("Dime tu red")`**: Formatea los inputs sosos de Grey Hack a `<color=#00e5ff>[?] Dime tu red </color>` limpiamente.
- **`modo ninja:`**: (Se declara arriba del todo). Engancha obligatoriamente a la salida final del código final un script que borra las variables del `syslog` dejando 0 rastros.
- **`tabla_str = construir_tabla(cabeceras, filas)`**: Motor propio de Nini para dibujar tablas ASCII invulnerables al bug de colores de `format_columns`. Resta el espectro invisible de los tags `<color>` para generar anchos y paddings perfectos antes de armar la tabla final para ti.
