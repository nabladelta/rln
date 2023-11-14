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
import { MemoryDatastore, NamespaceDatastore } from "datastore-core"
import { getTimestampInSeconds } from "./utils/time.js"

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

/**
 * Cretes & verifies RLN proofs
 */
export class RLN {
    public static protocol = '/rln/1.0.0'
    private provider: GroupDataProvider
    private identity: Identity
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
        for await (const value of this.store.query({prefix: `/nullifiers/${nullifier.toString(16)}`})) {
            proofs.push(deserializeProof(value.value))
        }
        return proofs
    }

    private async storeProof(proof: RLNGFullProof) {
        for (const nullifierString of proof.snarkProof.publicSignals.nullifiers) {
            // Ensure nullifier serialization is consistent
            const standardNullifierString = BigInt(nullifierString).toString(16)
            const key = new Key(`/nullifiers/${standardNullifierString}/${proof.snarkProof.publicSignals.signalHash}`)
            await this.store.put(key, serializeProof(proof))
        }
    }

    public async deleteProof(proof: RLNGFullProof) {
        for (const nullifierString of proof.snarkProof.publicSignals.nullifiers) {
            // Ensure nullifier serialization is consistent
            const standardNullifierString = BigInt(nullifierString).toString(16)
            const key = new Key(`/nullifiers/${standardNullifierString}/${proof.snarkProof.publicSignals.signalHash}`)
            await this.store.delete(key)
        }
    }

    public async deleteProofs(nullifier: bigint) {
        for await (const value of this.store.query({prefix: `/nullifiers/${nullifier.toString(16)}`})) {
            this.store.delete(value.key)
        }
    }

    private constructor(
        provider: GroupDataProvider,
        zkFiles: {wasmFilePath: string | Uint8Array, zkeyFilePath: string | Uint8Array, scheme: 'groth16' | 'plonk', vKey: any},
        store?: Datastore,
        secret?: string,
    ) {
        this.store = new NamespaceDatastore(store || new MemoryDatastore(), new Key(RLN.protocol))
        this.provider = provider
        this.identity = new Identity(secret)
        this.verifierSettings = {...zkFiles, userMessageLimitMultiplier: this.provider.getMultiplier(this.identity.commitment)!}
    }

    public static async load(secret: string, filename: string, store?: Datastore): Promise<RLN> {
        const provider = await FileProvider.load(filename)
        const {files, scheme, vKey} = getZKFiles('rln-multiplier-generic', 'groth16')
        return new RLN(provider, {...files, scheme, vKey}, store, secret)
    }

    public static async loadMemory(secret: string, groupData: GroupData, store?: Datastore) {
        const provider = await MemoryProvider.load(groupData)
        const {files, scheme, vKey} = getZKFiles('rln-multiplier-generic', 'groth16')
        return new RLN(provider, {...files, scheme, vKey}, store, secret)
    }

    public static async loadCustom(secret: string, provider: GroupDataProvider, {zkFiles, store}: {zkFiles?: {wasmFilePath: string | Uint8Array, zkeyFilePath: string | Uint8Array, scheme: 'groth16' | 'plonk', vKey: any}, store?: Datastore}) {
        if (!zkFiles) {
            const {files, scheme, vKey} = getZKFiles('rln-multiplier-generic', 'groth16')
            zkFiles = {...files, scheme, vKey}
        }
        return new RLN(provider, zkFiles, store, secret)
    }

    public async verify(proof: RLNGFullProof, claimedTime?: number) {
        const root = BigInt(proof.snarkProof.publicSignals.merkleRoot)
        const [start, end] = await this.provider.getRootTimeRange(root)
        if (!start) return VerificationResult.MISSING_ROOT

        const result = await verifyProof(proof, this.verifierSettings)

        if (!result) return VerificationResult.INVALID
        if (!claimedTime) return VerificationResult.VALID

        if (!(await this.provider.isRootNotExpiredAt(root, claimedTime))) return VerificationResult.OUT_OF_RANGE

        return VerificationResult.VALID
    }

    public async submitProof(proof: RLNGFullProof, claimedTime?: number, skipSlashing: boolean = false) {
        const res = await this.verify(proof, claimedTime)
        if (res == VerificationResult.INVALID || res == VerificationResult.MISSING_ROOT) {
            // There is no point in storing a proof that is either not correct, or from a different group
            return res
        }
        // Store proof
        await this.storeProof(proof)

        let slashes = 0
        for (let i = 0; i < proof.snarkProof.publicSignals.nullifiers.length; i++) {
            const nullifierString = proof.snarkProof.publicSignals.nullifiers[i]
            await this.lock.acquire(nullifierString, async () => {
                // Proofs with same nullifier
                const knownProofs = await this.getProofs(BigInt(nullifierString))
                // Find any that have same nullifier and a different signal
                const uniqueSignals = knownProofs.filter(p => 
                    p.snarkProof.publicSignals.signalHash 
                    !==
                    proof.snarkProof.publicSignals.signalHash)
                
                // Only one signal with this nullifier
                if (uniqueSignals.length == 1) return

                // We found a slashing target
                slashes++
                if (slashes > 1 || skipSlashing) return // Can't slash same user twice, or if we are skipping slashing

                const secret = await retrieveSecret(uniqueSignals, i)
                await this.provider.slash(secret)
                // Delete this proof after slashing.
                // If we don't it will just be in the store forever since the end-user 
                // of this library will know this proof was rejected, and won't store it, 
                // so he won't delete it later either.
                await this.deleteProof(proof)
            })
        }
        if (slashes > 0) return VerificationResult.BREACH

        return res
    }

    public async createProof(
            signal: string,
            externalNullifiers: nullifierInput[],
            rlnIdentifier: string,
            checkCache: boolean = false) {

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
            const res = await this.submitProof(proof, getTimestampInSeconds(), true)
            if (res === VerificationResult.BREACH) throw new Error("RLN breach detected")
        }
        return proof
    }
}