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

### Fase 1: Motor CLI y Estructura Múltiple
- [ ] Hacer que `nini.src` soporte el importado de archivos locales (`importar "modulo.nini"`) para dividir Revenant en pedazos manejables al transpilar.
- [ ] Construir la interfaz de comandos con nuestra UI `construir_tabla()`.

### Fase 2: Módulo Espectro (Reconocimiento Remoto)
- [ ] Usar `resolver_objetivo()` y la macro de puertos para reescribir el `wraith_net.src` en exactamente 5 líneas de Nini.

### Fase 3: Módulo Asalto (Inyecciones y Buffer Overflow Automático)
- [ ] Implementar la API de Metaxploit profunda en Nini.

### Fase 4: Persistencia Infinita (El Alma del Revenant)
- [ ] Automatizar rutinas de creación de backdoors `/etc/sysconfig` e inyectables en tareas de segundo plano que sobrevivan reinicios.

---
*Escrito por: Antigravity*
*Motor Asignado: Nini Transpiler V12*
