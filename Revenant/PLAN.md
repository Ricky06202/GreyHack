# Proyecto: REVENANT
*El Primer Framework de Post-Explotación Nativo 100% Nini*

## 1. El Concepto
Wraith fue nuestro primer gran proyecto: un framework pesado, dividido en docenas de archivos `.src` y basado puramente en MiniScript crudo. Era poderoso, pero sucio a nivel algorítmico y lleno de callbacks manuales, manejo crudo de IPs e inyecciones engorrosas de diccionarios WEP.

Ahora que tenemos a **Nini V12**, ha nacido el compilador más letal de Grey Hack. El sucesor lógico de Wraith no debería estar programado en MiniScript, debe ser el **primer software monumental programado exclusivamente en nuestro lenguaje `.nini`**. 

El nombre clave del proyecto es **Revenant** (El Renacido), porque usará los escombros de Wraith, pero volverá de entre los muertos limpio, invulnerable a caídas gracias a nuestro parser Null-Safety, inyectando `modo ninja:` automáticamente y conectando sus rutinas mediante el operador de tuberías (`>>`).

## 2. Arquitectura Base
Revenant operará directamente desde el transpilador. Consta de una consola principal en Nini que absorberá los módulos de inyección, escaneo y WiFi como si fueran Legos, reduciendo miles de líneas a un par de docenas de enunciados Nini.

```nini
// Ejemplo conceptual - main.nini
modo ninja:

[ip, port, modo] = requerir_argumentos("El objetivo es obligatorio", 3)

si modo == "destruir":
    ip >> buscar_vulnerabilidad(port) >> explotar("root") >> instalar_persistencia("daemon", 5555) >> saquear_sistema
osi modo == "enjambre":
    enjambre.añadir(ip)
    enjambre.lanzar_ddos_masivo(...)
```

## 3. Hoja de Ruta para Mañana

### Fase 0: Nini-Bundler (Herramienta Antigravity)
- [x] Desarrollar un empaquetador en **JavaScript (Bun)** que corra localmente en esta máquina para leer un `main.nini`.
- [x] Este script detectará cualquier `importar "archivo.nini"` y fusionará recursivamente todos los módulos en un solo archivo gigante y plano `revenant_bundle.nini`. 
- [x] Así, desarrollarás modularmente en Antigravity, pero solo copiarás y pegarás UNA VEZ un solo archivo monolítico dentro de Grey Hack. ¡Resolviendo el problema logístico de Greybel!

### Fase 1: Consola Interactiva (REPL a lo Metasploit)
- [x] Replicar la estructura Lisp de Clojette pero en sintaxis Nini para crear un bucle de consola invulnerable `Manejador_de_Estado = mientras 1: entrada = user_input("Revenant > ")`.
- [x] Construir la interfaz de ayuda tabular con `construir_tabla()`.
- [x] **NOTA ESTRATÉGICA:** El propósito real de este bucle infinito NO es solo escribir comandos; es para hospedar **Objetos de Shell Remote** en la memoria RAM `enjambre[IP_VICTIMA] = shell()`. Si Revenant termina su ejecución abrupta (como pasaba en el anterior framework), todas las conexiones a los servidores hackeados que hayamos recolectado se desconectarían y la variable se eliminaría por el Garabage Collector de Grey Hack. Este bucle mantiene viva nuestra "Botnet" para que podamos saltar de una IP a otra escribiendo *"usar 1"* o enviando comandos a 50 PCs simultáneamente sin volver a escanear ni compilar.

### Fase 2: Módulo Espectro (Reconocimiento Remoto)
- [x] Usar `resolver_objetivo()` y la macro de puertos para reescribir el `wraith_net.src` en exactamente 5 líneas de Nini.

### Fase 3: Módulo Asalto (Inyecciones y Buffer Overflow Automático)
- [x] Implementar la API de Metaxploit profunda en Nini.

### Fase 4: Persistencia Infinita (El Alma del Revenant)
- [x] Automatizar rutinas de creación de backdoors `/etc/sysconfig` e inyectables en tareas de segundo plano que sobrevivan reinicios.

---

## Estado Actual (Abril 2026)

### Completado
- Framework modular completo con 13+ módulos
- Sistema de vault cifrado
- Gestión de enjambre/botnet
- REPL interactivo
- Nini-Bundler funcional
- **Fix crítico:** Escaneo de red ahora verifica shell válido con `typeof()` y `resultado.ping("127.0.0.1")` para evitar falsos positivos
- Documentación completa

### Pendiente
- Testing en Grey Hack real
- WiFi cracking module
- Mejorar rendimiento de escaneo
