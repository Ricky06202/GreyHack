# GreyHack Development Workspace 💻🎮

Workspace de desarrollo para **Grey Hack** - un simulador de hacking donde programas en un lenguaje similar a MiniScript para crear herramientas de hacking.

## 📁 Estructura del Proyecto

```
GreyHack/
├── Nini/           # Motor de transpilación y APIs de hacking
├── Revenant/       # Framework de post-explotación modular
└── README.md       # Este archivo
```

## 🚀 Proyectos

### Nini - Transpilador & Motor de Exploits
Un transpilador de código Nini a MiniScript con macros automáticas para Grey Hack.

**Características:**
- Sintaxis minimalista estilo Python/espanglish
- Operadores pipelines (`>>`) y ternarios (`|:`)
- Inyección automática de APIs (`metaxploit.so`, `crypto.so`)
- Bucle Asíncrono (Background Workers)

```bash
cd Nini
bun bundler.js archivo.nini  # Empaquetar módulos
nini archivo.nini            # Transpilar (en Grey Hack)
```

### Revenant - Framework de Post-Explotación
Framework modular profesional con soporte completo de hacking en Grey Hack.

**Módulos:**
| Módulo | Función |
|--------|---------|
| `main` | Núcleo y comandos |
| `intel` | Credenciales y secretos |
| `asalto` | Explotación y pivoting |
| `red` | Topología de red |
| `vault` | Cifrado XOR de datos |
| `inyeccion` | Auto-replicación |
| `escalada` | Privesc a Root |

```bash
cd Revenant
bun ../Nini/nini-bundler/bundler.js main.nini  # Empaquetar
# Luego compilar revenant_bundle.nini en Grey Hack
```

## ⚡ Sintaxis Rápida Nini

```nini
// Condicionales
si puerto == 22: info("SSH")
osi puerto == 21: info("FTP")
sino: info("Otro")

// Bucles
para ip en red: escanear(ip)
for ip in red: escanear(ip)

// Ternario
resultado = x > 5 >> "mayor" |: "menor"

// Pipeline
obtener_target >> escanear >> explotar

// Funciones
tarea saludar(nombre): print("Hola " + nombre)
```

## 📚 Documentación

- [Nini - Guía Completa](Nini/README.md)
- [Revenant - Manual de Operación](Revenant/README.md)

## 🔧 Requisitos

- [Grey Hack](https://greyhacks.com/) (juego)
- [Bun.js](https://bun.sh/) (para el bundler)

---

*Desarrollado para Grey Hack - Donde el código es el arma.*