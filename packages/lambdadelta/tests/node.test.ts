import 'jest'
import createTestnet from '@hyperswarm/testnet'

import { FileProvider, GroupDataProvider } from 'bernkastel-rln'
import { Identity } from '@semaphore-protocol/identity'
import { existsSync, rmSync } from 'fs'
import { LDNode } from '../src/node'
import { Logger } from 'tslog'

const GROUP_FILE = 'testData.json'

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

const T = 'a'

describe('LDNode', () => {
    let anode: LDNode
    let bnode: LDNode
    let cnode: LDNode

    let destroy: () => Promise<void>

    beforeEach(async () => {
        const secretA = 'secret1secret1secret1'
        const secretB = 'secret1secret1secret2'
        const secretC = 'secret1secret1secret3'
        await FileProvider.write(
        [
            GroupDataProvider.createEvent(new Identity(secretA).commitment, 2),
            GroupDataProvider.createEvent(new Identity(secretB).commitment),
            GroupDataProvider.createEvent(new Identity(secretC).commitment, 5)
        ],
        GROUP_FILE)
        const mainLogger = new Logger({
            prettyLogTemplate: "{{yyyy}}-{{mm}}-{{dd}} {{hh}}:{{MM}}:{{ss}}:{{ms}} {{logLevelName}}\t[{{name}}]\t",
        })
        const logA = mainLogger.getSubLogger({name: 'nodeA'})
        const logB = mainLogger.getSubLogger({name: 'nodeB'})
        const logC = mainLogger.getSubLogger({name: 'nodeC'})

        const testnet = await createTestnet(3)
        anode = new LDNode(secretA, {logger: logA, memstore: true, swarmOpts: {bootstrap: testnet.bootstrap}})
        bnode = new LDNode(secretB, {logger: logB, memstore: true, swarmOpts: {bootstrap: testnet.bootstrap}})
        cnode = new LDNode(secretC, {logger: logC, memstore: true, swarmOpts: {bootstrap: testnet.bootstrap}})
        await anode.init()
        await bnode.init()
        await cnode.init()

        await anode.join([T])
        await bnode.join([T])
        await cnode.join([T])

        console.log('Initialized')
        
        destroy = async() => {
            if (existsSync(GROUP_FILE)) rmSync(GROUP_FILE, {force: true})
            await Promise.all([testnet.destroy(), anode.destroy(), bnode.destroy(), cnode.destroy()])
        }
    })

    afterEach(async () => {
        await destroy()
    })

    jest.setTimeout(120000)

    it('Joins topics', async () => {
        const a = anode.topicFeeds.get(T)!
        const b = bnode.topicFeeds.get(T)!
        const c = cnode.topicFeeds.get(T)!
        a.on('peerAdded', (peerID) => {
            console.log('added', peerID.slice(-6))
        })
        await sleep(5000)
        const aid = anode.peerId
        const bid = bnode.peerId
        const cid = bnode.peerId
        console.log('b', bid.slice(-6))
        expect(a.hasPeer(bid)).toBe(true)
        expect(a.hasPeer(cid)).toBe(true)
        expect(b.hasPeer(aid)).toBe(true)
        expect(b.hasPeer(cid)).toBe(true)
        expect(c.hasPeer(bid)).toBe(true)
        expect(c.hasPeer(aid)).toBe(true)
    })
})