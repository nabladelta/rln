import { Identity } from "@semaphore-protocol/identity"
import { GroupDataProvider } from "./providers/dataProvider.js"
import { FileProvider } from "./providers/file.js"
import { generateProof, nullifierInput, RLNGFullProof, verifyProof } from "./rlnProof.js"
import { getZKFiles } from "./utils/files.js"
import { retrieveSecret } from "./utils/recovery.js"
import { GroupData, MemoryProvider } from "./providers/memory.js"
import type { Datastore } from 'interface-datastore'
import AsyncLock from 'async-lock'
import { Key } from 'interface-datastore/key'
import { MemoryDatastore } from "datastore-core/memory"

export enum VerificationResult {
    VALID = "VALID",
    INVALID = "INVALID",
    MISSING_ROOT = "MISSING_ROOT",
    OUT_OF_RANGE = "OUT_OF_RANGE",
    DUPLICATE = "DUPLICATE",
    BREACH = "BREACH"
}
function stringToUint8Array(str: string): Uint8Array {
    const encoder = new TextEncoder()
    return encoder.encode(str)
}
function serializeProof(proof: RLNGFullProof) {
    return stringToUint8Array(JSON.stringify(proof))
}
function deserializeProof(serializedProof: Uint8Array): RLNGFullProof {
    return JSON.parse(new TextDecoder().decode(serializedProof))
}

async function getMemoryStore() {
    // const {MemoryDatastore} = await import('datastore-core/memory')
    return new MemoryDatastore()
}

/**
 * Cretes & verifies RLN proofs
 */
export class RLN {
    public static protocol = '/rln/1.0.0'
    private provider: GroupDataProvider
    private identity: Identity
    public expiredTolerance: number
    private store: Datastore // nullifier => Proof (cache)
    private lock = new AsyncLock({maxPending: 10000})
    private verifierSettings: {
        vKey: any,
        userMessageLimitMultiplier: number,
        scheme: 'groth16' | 'plonk'
        wasmFilePath: string | Uint8Array,
        zkeyFilePath: string | Uint8Array
    }

    public async getProofs(nullifier: bigint) {
        const proofs = []
        for await (const value of this.store.query({prefix: `${RLN.protocol}/nullifiers/${nullifier.toString()}`})) {
            proofs.push(deserializeProof(value.value))
        }
        return proofs
    }

    private async storeProof(nullifier: bigint, proof: RLNGFullProof) {
        const key = new Key(`${RLN.protocol}/nullifiers/${nullifier.toString()}/${proof.snarkProof.publicSignals.signalHash}`)
        return await this.store.put(key, serializeProof(proof))
    }

    public async deleteProof(nullifier: bigint, signalHash: string) {
        const key = new Key(`${RLN.protocol}/nullifiers/${nullifier.toString()}/${signalHash}`)
        return await this.store.delete(key)
    }

    private constructor(
        provider: GroupDataProvider,
        zkFiles: {wasmFilePath: string | Uint8Array, zkeyFilePath: string | Uint8Array, scheme: 'groth16' | 'plonk', vKey: any},
        store: Datastore,
        secret?: string,
    ) {
        this.store = store
        this.provider = provider
        this.expiredTolerance = 0
        this.identity = new Identity(secret)
        this.verifierSettings = {...zkFiles, userMessageLimitMultiplier: this.provider.getMultiplier(this.identity.commitment)!}
    }

    public static async load(secret: string, filename: string, store?: Datastore): Promise<RLN> {
        const provider = await FileProvider.load(filename)
        const {files, scheme, vKey} = getZKFiles('rln-multiplier-generic', 'groth16')
        return new RLN(provider, {...files, scheme, vKey}, store || await getMemoryStore(), secret)
    }

    public static async loadMemory(secret: string, groupData: GroupData, store?: Datastore) {
        const provider = await MemoryProvider.load(groupData)
        const {files, scheme, vKey} = getZKFiles('rln-multiplier-generic', 'groth16')
        return new RLN(provider, {...files, scheme, vKey}, store || await getMemoryStore(), secret)
    }

    public static async loadCustom(secret: string, provider: GroupDataProvider, {zkFiles, store}: {zkFiles?: {wasmFilePath: string | Uint8Array, zkeyFilePath: string | Uint8Array, scheme: 'groth16' | 'plonk', vKey: any}, store?: Datastore}) {
        if (!zkFiles) {
            const {files, scheme, vKey} = getZKFiles('rln-multiplier-generic', 'groth16')
            zkFiles = {...files, scheme, vKey}
        }
        return new RLN(provider, zkFiles, store || await getMemoryStore(), secret)
    }

    public async verify(proof: RLNGFullProof, claimedTime?: number) {
        const root = proof.snarkProof.publicSignals.merkleRoot
        const [start, end] = await this.provider.getRootTimeRange(BigInt(root))
        if (!start) return VerificationResult.MISSING_ROOT

        const result = await verifyProof(proof, this.verifierSettings)

        if (!result) return VerificationResult.INVALID
        if (!claimedTime) return VerificationResult.VALID
        if (!end
            && claimedTime >= start)
                return VerificationResult.VALID
        if (end
            && claimedTime >= start 
            && claimedTime <= (end + this.expiredTolerance)) 
                return VerificationResult.VALID

        return VerificationResult.OUT_OF_RANGE
    }

    public async submitProof(proof: RLNGFullProof, claimedTime?: number) {
        const res = await this.verify(proof, claimedTime)
        if (res == VerificationResult.INVALID || res == VerificationResult.MISSING_ROOT) {
            // There is no point in storing a proof that is either not correct, or from a different group
            return res
        }
        let slashes = 0
        for (let i = 0; i < proof.snarkProof.publicSignals.nullifiers.length; i++) {
            const nullifier = BigInt(proof.snarkProof.publicSignals.nullifiers[i])

            const res = await this.lock.acquire(nullifier.toString(), async () => {
                // Same nullifier
                const known = await this.getProofs(nullifier)
                // Find any that have same nullifier and signal
                const duplicates = known.filter(p => 
                    p.snarkProof.publicSignals.signalHash 
                    ===
                    proof.snarkProof.publicSignals.signalHash)

                if (duplicates.length > 0) {
                    return VerificationResult.DUPLICATE
                }
                // Not a duplicate proof, add it
                known.push(proof)
                await this.storeProof(nullifier, proof)
                // Not a duplicate, first one with this nullifier
                if (known.length == 1) return 'continue'

                // We found a slashing target
                slashes++
                if (slashes > 1) return 'continue' // Can't slash same user twice

                const secret = await retrieveSecret(known, i)
                await this.provider.slash(secret)
            })
            if (res == 'continue') continue
            if (res == VerificationResult.DUPLICATE) return res
            
        }
        if (slashes > 0) return VerificationResult.BREACH

        return res
    }

    public async createProof(
            signal: string,
            externalNullifiers: nullifierInput[],
            rlnIdentifier: string,
            checkCache: boolean = false,
            allowDuplicate: boolean = false) {

        const merkleProof = this.provider
            .createMerkleProof(
                this.identity.commitment,
                this.verifierSettings.userMessageLimitMultiplier)

        const proof = await generateProof(
            this.identity,
            merkleProof,
            externalNullifiers,
            signal,
            {
                rlnIdentifier,
               ...this.verifierSettings
            })

        if (checkCache) {
            for (const nullifier of proof.snarkProof.publicSignals.nullifiers) {
                const res = await this.lock.acquire(nullifier.toString(), async () => {
                    const proofs = await this.getProofs(BigInt(nullifier))

                    if (proofs.length > 0) {
                        if (!allowDuplicate) return VerificationResult.DUPLICATE

                        const differentSignalHash = proofs.filter(p => p.snarkProof.publicSignals.signalHash != proof.snarkProof.publicSignals.signalHash)
                        if (differentSignalHash.length > 0) return VerificationResult.BREACH
                    }
                    await this.storeProof(BigInt(nullifier), proof)
                })
                if (res === VerificationResult.DUPLICATE) throw new Error("Duplicate nullifier found")
                if (res === VerificationResult.BREACH) throw new Error("Duplicate signal hash found")
            }
        }
        return proof
    }
}