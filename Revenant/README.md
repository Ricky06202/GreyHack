# Revenant Hacking Framework 💀🌐
**The Ultimate Post-Exploitation Suite for Grey Hack.**

Revenant es un framework modular de hacking profesional construido sobre el motor **Nini**. Combina el sigilo de un fantasma con la potencia de un asalto frontal sincronizado.

## 🏗️ Arquitectura Modular
Revenant se divide en módulos especializados para cada fase del compromiso:
- **`main.nini`**: Núcleo y despacho de comandos.
- **`vault.nini`**: Persistencia cifrada XOR de credenciales y vulnerabilidades.
- **`intel.nini`**: Cosecha automatizada de secretos (Bank/Mail/Passwd).
- **`asalto.nini`**: Motor de explotación táctico con soporte de **Bounce** (Pivoting).
- **`red.nini`**: Descubrimiento y mapeo de topología de red.
- **`inyeccion.nini`**: Auto-replicación y despliegue del framework en targets.
- **`escalada.nini`**: Auditoría de vectores de Root (SetUID/Writeable).

---

## ⚡ Operación Ágil (Shortcuts)
Revenant está optimizado para la velocidad. Memoriza estos alias:

| Comando | Alias | Acción |
| :--- | :---: | :--- |
| `ayuda` | `h` | Muestra el panel de comandos |
| `objetivo` | `o` | Fija una IP/Dominio en la memoria global |
| `recon` | `r` | Escaneo Nmap inteligente |
| `asalto` | `a` | Explota y gana shell (Zero-Click) |
| `vault` | `v` | Visualiza el botín descifrado |
| `intel` | `i` | Saquea claves y bancos del target |
| `inject` | `inj` | Despliega Revenant en el sistema remoto |
| `privesc` | `p` | Busca fallos para escalar a Root |
| `red escanear`| `re`| Busca otros hosts en la red local |
| `red info` | `ri` | Muestra el mapa del enjambre |
| `salir` | `x / q` | Apagar el sistema |

---

## 🛡️ El Vault (Persistencia Cifrada)
Toda la información recolectada se guarda en `/var/revenant/vault.db`.
- **Cifrado:** XOR dinámico con clave `R3V3N4NT_S3CUR3`.
- **Caché de Vulns:** Si asaltas un servidor y guardas la vulnerabilidad, el siguiente asalto será instantáneo (bypass de escaneo).

## 🚀 Tácticas Avanzadas

### 1. El Salto (Bounce/Pivoting)
Si comprometes un router, puedes usarlo como puente para atacar IPs internas:
`Revenant > asalto` -> Detectará el router y te preguntará la IP interna.

### 2. Deep Intelligence
Al ejecutar `intel` (o `i`), el framework buscará en todos los usuarios:
- `Bank.txt` (Cracking automático de balance y cuenta).
- `Mail.txt` (Extracción de credenciales).
- `/etc/passwd` (Hash harvesting).

### 3. Inyección y Enjambre
`Revenant > inject` copiará el binario actual a `/bin` o `/tmp` del target, permitiéndote ejecutar el framework remotamente sin subir archivos manualmente.

---

## 📝 Sintaxis Nini
Revenant está escrito en **Nini**, un lenguaje que se transpila a MiniScript. Sintaxis rápida:

| Nini | MiniScript | Nota |
|------|------------|------|
| `si cond:` | `if cond then` | One-liner |
| `osi cond:` | `else if cond then` | |
| `sino:` | `else` | |
| `para x en col:` | `for x in col` | `for x in col:` también funciona |
| `recorrer col como x:` | `for x in col` | |
| `retornar` | `return` | |
| `mientras cond:` | `while cond` | |
| `intentar:` / `excepto:` | try/catch | |
| `>>` | Pipeline | `a >> b()` = `b(a)` |
| `x >> val1 \|: val2` | Ternario | Genera `if/else` |

**Ternarios:** `cond >> valor_si_verdadero |: valor_si_falso`

**One-liners:** `si cond: accion` / `para x en col: accion`

---

**"No somos errores en el sistema. Somos el sistema recuperando su memoria."**
*Desarrollado sobre Nini Engine.*
