import 'jest'
import { existsSync, readFileSync, rmSync } from "fs"
import { GroupDataProvider } from '../src/core/rln/providers/dataProvider'
import { FileProvider } from '../src/core/rln/providers/file'
import { Lambda, VerificationResult } from '../src/core/rln/lambda'
import { getTimestampInSeconds } from '../src/core/utils/utils'
import { Identity } from '@semaphore-protocol/identity'

describe.only('RLN', () => {
    it('Creates groups, proofs, verifies, rejects', async () => {
        if (existsSync('groupData.json')) rmSync('groupData.json', {force: true})
        const secret1 = "john"
        const secret2 = "steve"
        const enullifiers = [
            {nullifier: "Test nullifier1", messageId: 10, messageLimit: 6},
            {nullifier: "Test nullifier2", messageId: 3, messageLimit: 7}] 
        await FileProvider.write(
            [
                GroupDataProvider.createEvent(new Identity(secret1).commitment, 2),
                GroupDataProvider.createEvent(new Identity(secret2).commitment)
            ],
            'groupData.json')

        const [lambda, delta] = await Lambda.load(secret1)
        const proof = await delta.createProof('test', enullifiers, "1")
        const result = await lambda.verify(proof, getTimestampInSeconds())
        expect(result).toEqual(VerificationResult.VALID)
        
        const [lambdaB, deltaB] = await Lambda.load(secret2)
        expect(async () => deltaB.createProof('test', enullifiers, "1")).rejects
        if (existsSync('groupData.json')) rmSync('groupData.json', {force: true})
    })

    it('Submit proofs', async () => {
        if (existsSync('groupData.json')) rmSync('groupData.json', {force: true})
        const secret1 = "john"
        const secret2 = "steve"
        const enullifiers = [
            {nullifier: "Test nullifier1", messageId: 10, messageLimit: 6},
            {nullifier: "Test nullifier2", messageId: 3, messageLimit: 7}] 
        await FileProvider.write(
            [
                GroupDataProvider.createEvent(new Identity(secret1).commitment, 2),
                GroupDataProvider.createEvent(new Identity(secret2).commitment)
            ],
            'groupData.json')

        const [lambda, delta] = await Lambda.load(secret1)
        const proof = await delta.createProof('test', enullifiers, "1")
        const result = await lambda.submitProof(proof, getTimestampInSeconds())
        expect(result).toEqual(VerificationResult.VALID)
        
        const r2 = await lambda.submitProof(proof, getTimestampInSeconds())
        expect(r2).toEqual(VerificationResult.DUPLICATE)

        const e2nullifiers = [
            {nullifier: "2", messageId: 10, messageLimit: 6},
            {nullifier: "3", messageId: 3, messageLimit: 7}
        ]
        const p3 = await delta.createProof('test', e2nullifiers, "1")
        const r3 = await lambda.submitProof(p3, 100)
        expect(r3).toEqual(VerificationResult.OUT_OF_RANGE)

        const p4 = await delta.createProof('test2', e2nullifiers, "1")
        const r4 = await lambda.submitProof(p4, getTimestampInSeconds())
        expect(r4).toEqual(VerificationResult.BREACH)

        const r5 = await lambda.submitProof(p4, getTimestampInSeconds())
        expect(r5).toEqual(VerificationResult.DUPLICATE)

        const r6 = await lambda.submitProof(p4, 100)
        expect(r6).toEqual(VerificationResult.DUPLICATE)

        expect(async () => await delta.createProof('test2', e2nullifiers, "1")).rejects
        if (existsSync('groupData.json')) rmSync('groupData.json', {force: true})
    })
})