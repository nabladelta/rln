import { readFileSync } from "fs"
import path from "path"
import { dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export function getZKFiles(name: string, scheme: 'groth16' | 'plonk' = 'groth16') {
    const circuitpath = path.join(__dirname, '..', '..', 'compiled', name)
    const vkeyPath = path.join(circuitpath, scheme, "verification_key.json")
    const vKey = JSON.parse(readFileSync(vkeyPath, "utf-8"))
    const wasmFilePath = path.join(circuitpath, "js", "circuit.wasm")
    const zkeyFilePath = path.join(circuitpath, scheme, "final.zkey")
    return {vKey, files: {wasmFilePath, zkeyFilePath}, scheme}
}