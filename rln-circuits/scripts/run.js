const { execSync } = require("child_process")
const { mkdirSync, renameSync, rmSync, existsSync } = require('fs')
const path = require('path')
const crypto = require('crypto')

const fs = require('fs')
const https = require('https')

function execPrint(cmd) {
    console.log(execSync(cmd).toString())
}


async function run(name, scheme, tauname) {
    const root = process.cwd()
    const tauFile = path.join(root, 'tau', tauname)
    const build = path.join(root, 'build')
    const circuitFile = path.join(root, 'circuits', name+'.circom')
    const setup = path.join(build, 'setup', scheme, name)

    const rlnlib = path.join(root, '..')
    const dest = path.join(rlnlib, 'compiled', name)
    if (!existsSync(tauFile)) {
        const tauURL = `https://hermez.s3-eu-west-1.amazonaws.com/${tauname}`
        mkdirSync(path.join(root, 'tau'), {recursive: true})
        console.log(`Downloading ${tauURL} and saving it to ${tauFile}`)
        try {
            await downloadFile(tauURL, tauFile)
        } catch (e) {
            console.error(e)
            process.exit(1)
        }
    }
    rmSync(build, {recursive: true, force: true})

    mkdirSync(setup, {recursive: true})
    mkdirSync(path.join(dest, scheme), {recursive: true})

    process.chdir(build)
    execPrint(`circom ${circuitFile} --r1cs --wasm --sym`)

    rmSync(path.join(dest, 'js'), {recursive: true, force: true})
    renameSync(path.join(build, `${name}_js`, `${name}.wasm`), path.join(build, `${name}_js`, `circuit.wasm`))
    renameSync(path.join(build, `${name}_js`), path.join(dest, 'js'), {force: true})

    execPrint(`snarkjs r1cs export json ${name}.r1cs ${name}.r1cs.json`)
    if (scheme == 'groth16') {
        execPrint(`snarkjs groth16 setup ${name}.r1cs ${tauFile} ${path.join(setup, 'rln_0000.zkey')} `)
        execPrint(`snarkjs zkey contribute ${path.join(setup, 'rln_0000.zkey')} ${path.join(setup, 'rln_0001.zkey')} --name="First contribution" -v -e="${crypto.randomBytes(16).toString('hex')}"`)
        execPrint(`snarkjs zkey contribute ${path.join(setup, 'rln_0001.zkey')} ${path.join(setup, 'rln_0002.zkey')} --name="Second contribution" -v -e="${crypto.randomBytes(16).toString('hex')}"`)
        execPrint(`snarkjs zkey beacon ${path.join(setup, 'rln_0002.zkey')} ${path.join(setup, 'final.zkey')} 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon phase2"`)
        // Copy intermediate setup files
        rmSync(path.join(dest, scheme, 'setup'), {recursive: true, force: true})
        mkdirSync(path.join(dest, scheme, 'setup'), {recursive: true})
        renameSync(path.join(setup, 'rln_0000.zkey'), path.join(dest, scheme, 'setup', 'rln_0000.zkey'))
        renameSync(path.join(setup, 'rln_0001.zkey'), path.join(dest, scheme, 'setup', 'rln_0001.zkey'))
        renameSync(path.join(setup, 'rln_0002.zkey'), path.join(dest, scheme, 'setup', 'rln_0002.zkey'))
    } else if (scheme == 'plonk') {
        execPrint(`snarkjs plonk setup ${name}.r1cs ${tauFile} ${path.join(setup, 'final.zkey')} `)
    } else if (scheme == 'fflonk') {
        execPrint(`snarkjs fflonk setup ${name}.r1cs ${tauFile} ${path.join(setup, 'final.zkey')} `)
    } else {
        console.error("Invalid scheme")
        return
    }
    execPrint(`snarkjs zkey export verificationkey ${path.join(setup, 'final.zkey')} ${path.join(dest, scheme, 'verification_key.json')}`)
    execPrint(`snarkjs zkey export solidityverifier ${path.join(setup, 'final.zkey')}  ${path.join(dest, scheme, 'verifier.sol')}`)
    renameSync(path.join(setup, 'final.zkey'), path.join(dest, scheme, 'final.zkey'))
    process.chdir(root)
    rmSync(build, {recursive: true})
}
async function build() {
    // await run('rln', 'groth16', "powersOfTau28_hez_final_17.ptau")
    // await run('rln-multi', 'groth16', "powersOfTau28_hez_final_17.ptau")
    // await run('rln-same-dual', 'groth16', "powersOfTau28_hez_final_17.ptau")
    // await run('rln', 'plonk', "powersOfTau28_hez_final_17.ptau")
    // await run('rln-multi', 'plonk', "powersOfTau28_hez_final_17.ptau")
    // await run('rln-same-dual', 'plonk', "powersOfTau28_hez_final_17.ptau")
    await run('rln-multiplier-generic', 'groth16', "powersOfTau28_hez_final_17.ptau")
    process.exit()
}

function download(url, dest, cb, errcb) {
    const file = fs.createWriteStream(dest)

    const request = https.get(url, (response) => {
        // check if response is success
        if (response.statusCode !== 200) {
            return errcb('Response status was ' + response.statusCode)
        }

        response.pipe(file)
    })

    // close() is async, call cb after close completes
    file.on('finish', () => file.close(cb))

    // check for request error too
    request.on('error', (err) => {
        fs.unlink(dest, () => errcb(err.message)) // delete the (partial) file and then return the error
    })

    file.on('error', (err) => { // Handle errors
        fs.unlink(dest, () => errcb(err.message)) // delete the (partial) file and then return the error
    })
}

async function downloadFile(url, file) {
    return new Promise((resolve, reject) => {download(url, file, resolve, reject)})
}

build()