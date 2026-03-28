const vscode = require('vscode');

const niniDocs = {
    "modo": {
        title: "Modo Nini OS",
        body: "Declaración preprocesador para activar rutinas en el transpilador. Generalmente usado antes del script como `modo ninja:`."
    },
    "ninja:": {
        title: "Nini Ninja Cleanup",
        body: "Borra automáticamente **`/var/system.log`** y elimina el **archivo temporal `.gs`** de la PC host/atacante tras su compilación exitosa, cubriendo el rastro visual en pantalla."
    },
    "escanear": {
        title: "Auto-Scanner Nmap (Macro)",
        body: "Requiere que exista un `target_ip` definido previamente y un `router` (vía `mirar()`). Analiza cada puerto retornando una lista de puertos y escribiendo **`scan_[ip].txt`**."
    },
    "mirar": {
        title: "API Nini: mirar(ip)",
        body: "Instancia y obtiene un nodo de enrutador mediante `get_router(ip)` preparándolo para macros consecuentes como `escanear`."
    },
    "buscar_vulnerabilidad": {
        title: "API Nini: buscar_vulnerabilidad(ip, puerto)",
        body: "Llama sigilosamente a **`metaxploit`**, conectando al objetivo. Retorna un map `{metalib: Metalib, mem: MemoryAddress}` con el primer fallo crudo hallado."
    },
    "crackear_diccionario": {
        title: "API Nini: crackear_diccionario(shadow_text)",
        body: "Itera brutalmente por líneas de un dump de shadow. Usa `crypto.decipher()`. Retorna los diccionarios limpios dentro de la variable global Nini `__nini_res_crack`."
    },
    "resolver_objetivo": {
        title: "API Nini: resolver_objetivo(ip_o_dominio)",
        body: "Determina independientemente si usar `nslookup()` o retornarlo crudo como IP local válida. Maneja sus propias caídas silenciosas si no hay respuesta."
    },
    "enjambre": {
        title: "Enjambre de Memoria (Revenant OS)",
        body: "Diccionario global utilizado por Revenant para almacenar de forma inquebrantable shells remotas o computadoras parasitadas temporalmente en RAM."
    },
    "pedir": {
        title: "Nini-UI: pedir(prompt_msg)",
        body: "Sustituto estilizado de Grey Hack `user_input()`. Despliega el string en cyan con un delimitador rojo/hacker `[?]`."
    },
    "exito": {
        title: "Nini-UI: exito(texto)",
        body: "Muestra la palabra `[SUCCESS]` en formato enriquecido por consola y el mensaje adjunto en color verde lima."
    },
    "info": {
        title: "Nini-UI: info(texto)",
        body: "Imprime información direccional estandarizada en pantalla blanca."
    },
    "error": {
        title: "Nini-UI: error(texto)",
        body: "Detona una alarma visual `[ERROR]` en color escarlata sangriento."
    },
    "explotar": {
        title: "Pipeline Macro: explotar(password)",
        body: "Invocado como `vuln >> explotar(\"pass\")`. Inyecta el buffer overflow sobre la dirección de memoria pre-adquirida con sintaxis Spanglish."
    },
    "importar": {
        title: "Directiva: importar \"archivo.nini\"",
        body: "Macro de pre-compilación gestionada por Nini-Bundler. Empiqueta y fusiona módulos `Bun/JS` automáticamente en un solo bloque bruto antes de ir a Grey Hack."
    },
    "tarea": {
        title: "Declaración de Tarea (Función Nini)",
        body: "Define una función. Sintaxis: `tarea nombre:` (multilínea) o `tarea nombre: codigo` (one-liner). Se convierte a `nombre = function() ... end function`."
    },
    "funcion": {
        title: "Declaración de Función",
        body: "Alias de tarea. Sintaxis: `funcion nombre:` o `funcion nombre: return valor`."
    },
    // ---- [GREYSCRIPT RETROCOMPATIBILIDAD] ----
    "print": {
        title: "GreyScript API: print(text)",
        body: "Imprime texto en la terminal. Soporta envoltorios `HTML` de motor Unity tales como `<color=red>texto</color>`."
    },
    "get_shell": {
        title: "GreyScript API: get_shell(username, password)",
        body: "Retorna el objeto local `shell`. Si se proveen el usuario y contraseña del host, retorna de inmediato escalada local."
    },
    "get_router": {
        title: "GreyScript API: get_router(ip)",
        body: "Instancia virtualmente un router remoto. Expone propiedades topológicas como `used_ports` o `public_ip`."
    },
    "include_lib": {
        title: "GreyScript API: include_lib(path)",
        body: "Invoca librerías compartidas dentro de la máquina actual (ej. `/lib/metaxploit.so`). Retorna el framework o falso en fallo de permisos."
    },
    "user_input": {
        title: "GreyScript API: user_input(prompt)",
        body: "Espera input síncrono del teclado local del jugador. *Nota de Framework: Ha sido superado estilísticamente por la macro 'pedir' de Nini.*"
    },
    "current_path": {
        title: "GreyScript Propiedad: current_path",
        body: "Devuelve limpiamente la carpeta local completa de donde el ejecutable actual `.exe` o script `.gs` se lanzó para resolver rutas dinámicamente."
    },
    "typeof": {
        title: "GreyScript Runtime: typeof(variable)",
        body: "Explora la estructura virtual del objeto. Sus valores más potentes a atajar suelen ser `\"shell\"` y `\"computer\"` tras una inyección de lib."
    },
    "File": {
        title: "GreyScript FS: object.File(path_string)",
        body: "Invocable puramente y exclusivamente solo sobre objetos `shell.host_computer` o `computer` hackeados. Retorna Nulo de no localizarlo."
    },
    "nslookup": {
        title: "GreyScript Red: nslookup(dominio)",
        body: "Resuelve DNS. Empleado nativamente adentro de la función maestra `resolver_objetivo` de nuestro framework Revenant."
    },
    "|=": {
        title: "Operador Ternario (|:)",
        body: "Condicional inline moderno. Sintaxis: `condición >> valor_true |: valor_false`. Ejemplo: `x == 5 >> \"si\" |: \"no\"` se traduce a `if x == 5 then \"si\" else \"no\" end if`."
    }
};

async function provideDefinition(document, position, token) {
    const range = document.getWordRangeAtPosition(position, /[a-zA-Z0-9_]+/);
    if (!range) return null;

    const word = document.getText(range);
    
    try {
        // En un workspace grande, podríamos restringirlo. Buscar todas las ocurrencias de `tarea X:`
        const uris = await vscode.workspace.findFiles('**/*.nini');
        
        for (const uri of uris) {
            const doc = await vscode.workspace.openTextDocument(uri);
            const text = doc.getText();
            
            // Regex para capturar `tarea NOMBRE_WORD:` o variaciones
            const regex = new RegExp(`^\\s*tarea\\s+${word}\\s*:`, 'm');
            const match = text.match(regex);
            
            if (match) {
                // Calcular coordenadas para el IDE
                const lines = text.substring(0, match.index).split('\\n');
                const lineNumber = lines.length > 0 ? lines.length - 1 : 0;
                // La posicion de la palabra en la linea
                const lineContent = doc.lineAt(lineNumber).text;
                const charPos = lineContent.indexOf(word);
                
                const hoverPosition = new vscode.Position(lineNumber, Math.max(0, charPos));
                return new vscode.Location(uri, hoverPosition);
            }
        }
    } catch(err) {
        console.error("Nini GoToDefinition Error:", err);
    }
    return null;
}

function activate(context) {
    const hoverProvider = vscode.languages.registerHoverProvider('nini', {
        provideHover(document, position, token) {
            // Evaluamos identificadores clave (Nombres de funciones + ":" opcional)
            const range = document.getWordRangeAtPosition(position, /[a-zA-Z0-9_:]+/);
            if (!range) return;

            const word = document.getText(range);
            
            if (niniDocs[word]) {
                const doc = niniDocs[word];
                const markdown = new vscode.MarkdownString();
                markdown.appendMarkdown(`### \u26A1 ${doc.title}\n---\n${doc.body}`);
                return new vscode.Hover(markdown);
            }
        }
    });

    const defProvider = vscode.languages.registerDefinitionProvider('nini', {
        provideDefinition
    });

    context.subscriptions.push(hoverProvider, defProvider);
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
}
