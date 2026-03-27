import { readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve, dirname, join } from 'path';

function bundle(inputFile, outputFile) {
    const visited = new Set();
    
    function processFile(filePath) {
        const absPath = resolve(filePath);
        if (visited.has(absPath)) return ''; // Prevent circular imports
        visited.add(absPath);
        
        if (!existsSync(absPath)) {
            console.error(`❌ Error critico: El modulo '${absPath}' no existe.`);
            process.exit(1);
        }
        
        const content = readFileSync(absPath, 'utf-8');
        const lines = content.split('\n');
        const outputLines = [];
        
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const trimmed = line.trim();
            
            // Detectar directiva: importar "modulo.nini"
            const importMatch = trimmed.match(/^importar\s+"([^"]+)"$/);
            
            if (importMatch) {
                const importFile = importMatch[1];
                const importPath = join(dirname(absPath), importFile);
                console.log(`📦 Empaquetando submódulo: ${importFile}`);
                
                outputLines.push(`// --- INICIO SUB-MODULO: ${importFile} ---`);
                outputLines.push(processFile(importPath));
                outputLines.push(`// --- FIN SUB-MODULO: ${importFile} ---`);
            } else {
                outputLines.push(line);
            }
        }
        return outputLines.join('\n');
    }

    console.log(`🚀 Iniciando Nini-Bundler: Leyendo árbol de dependencias desde ${inputFile}`);
    const bundledContent = processFile(inputFile);
    
    writeFileSync(outputFile, bundledContent);
    console.log(`\n✅ Ensamblaje completado con éxito!`);
    console.log(`📁 Código monolítico exportado a: ${outputFile}`);
    console.log(`💡 Solo necesitas copiar y compilar el archivo generado en Grey Hack.`);
}

const args = process.argv.slice(2);
if (args.length < 1) {
    console.log("Uso: bun bundler.js <archivo_principal.nini> [archivo_salida.nini]");
    process.exit(1);
}

const inputFile = args[0];
const outputFile = args[1] || inputFile.replace('.nini', '_bundle.nini');

bundle(inputFile, outputFile);
