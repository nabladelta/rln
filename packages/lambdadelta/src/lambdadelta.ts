import BTree from 'sorted-btree'
import b4a from 'b4a'
import Hyperdrive from 'hyperdrive'
import crypto from 'crypto'
import { TypedEmitter } from 'tiny-typed-emitter'
import { RLN, RLNGFullProof, VerificationResult, nullifierInput } from 'bernkastel-rln'
import { deserializeEvent, deserializeFeedEntry,
    getEpoch, getMean, getStandardDeviation,
    getTimestampInSeconds,
    mostCommonElement,
    serializeEvent,
    serializeFeedEntry } from './utils'
import Corestore from 'corestore'
import Hypercore from 'hypercore'

const TOLERANCE = 10
const CLAIMED_TOLERANCE = 60
const TIMEOUT = 5000
const QUORUM = 66/100

/**
 * @typedef FeedEventHeader Our main Event type
 * @property {string} eventType Event type
 * @property {number} claimed Time the event author claims
 * @property {RLNGFullProof} proof RLN proof for this event
 * @property {string} contentHash Hash of content
 */
export interface FeedEventHeader {
    eventType: string
    claimed: number
    proof: RLNGFullProof
    contentHash: string
}

/**
 * @typedef FeedEntry An entry in our feed hypercore
 * @property {number} oldestIndex Index of the oldest still valid block
 * @property {number} received Timestamp in seconds
 * @property {string} eventID The event's ID
 */
export interface FeedEntry {
    received: number
    oldestIndex: number
    eventID: string
}

/**
 * @typedef NullifierSpec Spec for a nullifier
 * @property {number} epoch Epoch length in seconds
 * @property {number} messageLimit Message limit per epoch
 */
export interface NullifierSpec {
    epoch: number
    messageLimit: number
}

interface TopicEvents {
    'peerAdded': (memberCID: string) => void
    'peerRemoved': (memberCID: string) => void
    'publishReceivedTime': (eventID: string, time: number) => void
    'syncFatalError': (
            memberCID: string,
            error: VerificationResult | HeaderVerificationError | ContentVerificationResult) => void
    'syncEventResult': (
            memberCID: string, 
            headerResult: VerificationResult | HeaderVerificationError,
            contentResult: ContentVerificationResult | undefined) => void
    'syncContentResult': (memberCID: string, contentResult: ContentVerificationResult) => void
    'syncDuplicateEvent': (
            memberCID: string,
            eventID: string,
            index: number,
            prevIndex: number | undefined) => void
    'syncEventReceivedTime': (memberCID: string, eventID: string, received: number) => void
    'timelineAddEvent': (eventID: string, time: number, consensusTime: number) => void
    'timelineRemoveEvent': (eventID: string, prevTime: number, consensusTime: number) => void
    'timelineRejectedEvent': (eventID: string, claimedTime: number, consensusTime: number) => void
    'consensusTimeChanged': (eventID: string, prevTime: number, newTime: number) => void
}

interface EventMetadata {
    index: number // Index on own hypercore
    received: number // Time received for us
    claimed: number // Time the event was supposedly produced
    consensus: number
    membersReceived: Map<string, number> // MemberCID => time received
}

interface PeerData {
    lastIndex: number // Last index we scanned
    events: Map<string, number> // All events we obtained from this peer => index on core
    feedCore: Hypercore
    drive: Hyperdrive
    finishedInitialSync: boolean,
    _onappend: () => Promise<void>
}

enum ContentVerificationResult {
    VALID,
    UNAVAILABLE,
    SIZE,
    HASH_MISMATCH,
    INVALID
}

enum HeaderVerificationError {
    HASH_MISMATCH = 16, // Make sure we don't overlap with other enums
    UNEXPECTED_RLN_IDENTIFIER,
    UNEXPECTED_MESSAGE_LIMIT,
    UNEXPECTED_NULLIFIER,
    UNAVAILABLE,
    SIZE
}

/**
 * Decentralized Multi-writer event feed for a `topic`
 * with timestamps based on local consensus
 * and rate limiting through RLN
 */
export class Lambdadelta extends TypedEmitter<TopicEvents> {
    private corestore: Corestore
    public topic: string

    // RLN
    private rln: RLN

    private timeline: BTree<number, string> // Timestamp (ms) => EventID
    private eidTime: Map<string, number> // EventID => Timestamp (ms)

    private core: any // Hypercore
    private drive: any // Hyperdrive
    private oldestIndex: number // Our oldest valid event index

    protected nullifierSpecs: Map<string, NullifierSpec[]>
    protected maxContentSize: Map<string, number>

    private eventMetadata: Map<string, EventMetadata> // EventID => Metadata
    private peers: Map<string, PeerData> // MemberCID => Hypercore

    constructor(topic: string, corestore: Corestore, rln: RLN) {
        super()
        this.topic = topic
        this.rln = rln
        this.oldestIndex = 0

        this.timeline = new BTree()
        this.peers = new Map()
        this.eidTime = new Map()
        this.nullifierSpecs = new Map()
        this.eventMetadata = new Map()
        this.maxContentSize = new Map()

        this.corestore = corestore.namespace('lambdadelta')
        this.core = this.corestore.get({ name: topic })
        this.drive = new Hyperdrive(this.corestore)
    }

    public async ready() {
        await this.core.ready()
        await this.drive.ready()
    }

    public hasPeer(memberCID: string) {
        return this.peers.has(memberCID)
    }

    /**
     * Sets an event's timestamp in the internal timeline
     * @param time The event's timestamp in seconds
     * @param eventID The event's ID
     * @returns The previously saved timestamp (ms), or undefined
     */
    private setTime(eventID: string, time: number) {
        const prevTime = this.eidTime.get(eventID)
        if (prevTime) { // Already existing key
            if (!this.timeline.delete(prevTime)){
                throw new Error("Key was missing from timeline")
            }
        }
        let newTime = time * 1000 // Convert to ms
        while(!this.timeline.setIfNotPresent(newTime, eventID)) {
            // Keep trying with a newer time until we find an empty spot
            newTime++
        }
        this.eidTime.set(eventID, newTime)
        return prevTime
    }

    private unsetTime(eventID: string) {
        const prevTime = this.eidTime.get(eventID)
        if (prevTime) { // Already existing key
            if (!this.timeline.delete(prevTime)){
                throw new Error("Key was missing from timeline")
            }
        }
        this.eidTime.delete(eventID)
        return prevTime
    }

    public getCoreIDs(): [string, string] {
        return [this.core.key.toString('hex'), this.drive.key.toString('hex')]
    }

    public async getCoreLength(): Promise<number> {
        await this.core.ready()
        return this.core.length
    }

    public async close() {
        for (let [id, peer] of this.peers) {
            peer.feedCore.removeListener('append', peer._onappend)
        }
        for (let [id, peer] of this.peers) {
            await peer.drive.close()
            await peer.feedCore.close()
        }
    }

    public async addPeer(memberCID: string, feedCoreID: string, driveID: string) {
        if (this.peers.has(memberCID)) {
            // Peer already added
            return false
        }
        const feedCore = this.corestore.get(b4a.from(feedCoreID, 'hex'))
        const drive = new Hyperdrive(this.corestore, b4a.from(driveID, 'hex'))
        await feedCore.ready()
        await drive.ready()
        const peer = {
            feedCore,
            drive,
            lastIndex: 0,
            events: new Map(),
            finishedInitialSync: false,
            _onappend: async () => {
                await this.syncPeer(memberCID, false)
            }
        }
        this.peers.set(memberCID, peer)
        this.emit('peerAdded', memberCID)
        const completed = await this.syncPeer(memberCID, true)
        if (!completed) return false // Sync did not complete successfully
        feedCore.on('append', peer._onappend)
        return true
    }

    public async removePeer(memberCID: string) {
        const peer = this.peers.get(memberCID)
        if (!peer) {
            // Peer does not exist
            return false
        }
        peer.feedCore.removeListener('append', peer._onappend)
        this.peers.delete(memberCID)
        await peer.drive.close()
        await peer.feedCore.close()
        // Remove peer's received timestamps contributions
        for (let [eventID, _] of peer.events) {
            const eventMetadata = this.eventMetadata.get(eventID)
            if (!eventMetadata) {
                continue
            }
            eventMetadata.membersReceived.delete(memberCID)
            this.eventMetadata.set(eventID, eventMetadata)
            await this.onMemberReceivedTime(eventID)
        }
        this.emit('peerRemoved', memberCID)
        return true
    }

    protected onInvalidInput(
            memberCID: string,
            headerResult: VerificationResult | HeaderVerificationError | undefined,
            contentResult: ContentVerificationResult | undefined
        ) {

        if (headerResult !== undefined) {
            if (headerResult === HeaderVerificationError.UNAVAILABLE) {
                return true
            }
            this.removePeer(memberCID)
            this.emit('syncFatalError', memberCID, headerResult)
            return false
        }

        if (contentResult !== undefined) {
            if (contentResult === ContentVerificationResult.UNAVAILABLE) {
                return true
            }
            this.removePeer(memberCID)
            this.emit('syncFatalError', memberCID, contentResult)
            return false
        }

        return true
    }

    protected async onDuplicateInput(
            memberCID: string,
            eventID: string,
            index: number,
            prevIndex: number | undefined) {
        
        const peer = this.peers.get(memberCID)
        if (!peer) {
            throw new Error("Unknown peer")
        }
        if (index === prevIndex && index !== undefined && prevIndex !== undefined) {
            throw new Error("Scanned same index entry twice")
        }
        if (prevIndex === undefined) {
            throw new Error("Index confusion")
        }

        const entryBufA: Buffer = await peer.feedCore.get(prevIndex, {timeout: TIMEOUT})
        const entryA = deserializeFeedEntry(entryBufA)

        const entryBufB: Buffer = await peer.feedCore.get(index, {timeout: TIMEOUT})
        const entryB = deserializeFeedEntry(entryBufB)

        if (entryA.eventID == entryB.eventID) {
            this.emit('syncDuplicateEvent', memberCID, eventID, index, prevIndex)
            await this.removePeer(memberCID)
        }

        return false
    }

    private async syncPeer(memberCID: string, initialSync: boolean): Promise<boolean> {
        const peer = this.peers.get(memberCID)
        if (!peer) {
            throw new Error("Unknown peer")
        }

        if (!initialSync && !peer.finishedInitialSync) {
            throw new Error("Trying to sync new events before finishing initial sync")
        }

        await peer.feedCore.ready()
        // if (peer.feedCore.length < 1) {
        //     throw new Error("Peer core is empty")
        // }
        let startFrom = peer.lastIndex + 1

        if (initialSync && peer.lastIndex == 0) {
            // Find the first valid entry
            const lastEntryBuf: Buffer = await peer.feedCore.get(peer.feedCore.length - 1, {timeout: TIMEOUT})
            const lastEntry = deserializeFeedEntry(lastEntryBuf)
            startFrom = lastEntry.oldestIndex
        }

        for (let i = startFrom; i < peer.feedCore.length; i++) {
            const shouldContinue = await this.syncEntry(memberCID, i, initialSync)
            // Interrupt synchronization from this peer immediately
            if (!shouldContinue) return false
        }

        peer.finishedInitialSync = true
        this.peers.set(memberCID, peer)
        return true
    }

    private async syncEntry(memberCID: string, i: number, initialSync: boolean): Promise<boolean> {
        const peer = this.peers.get(memberCID)
        if (!peer) {
            throw new Error("Unknown peer")
        }

        const entryBuf: Buffer = await peer.feedCore.get(i, {timeout: TIMEOUT})
        const entry = deserializeFeedEntry(entryBuf)
        const eventID = entry.eventID

        let claimedTime: number | undefined
        let headerResult: HeaderVerificationError | VerificationResult | undefined
        let contentResult: ContentVerificationResult | undefined

        if (!(await this.drive.entry(`/events/${eventID}/header`))) {
            // We never encountered this event before
            const results = await this.syncEvent(memberCID, eventID)
            headerResult = results.headerResult
            contentResult = results.contentResult
            claimedTime = results.claimedTime
            this.emit('syncEventResult', memberCID, results.headerResult, results.contentResult)

        } else if (!(await this.drive.entry(`/events/${eventID}/content`))) {
            // In this case we have the header, but we are missing the content
            // Probably from a previous peer not having it, or having an invalid version of it, etc
            const results = await this.syncContent(memberCID, eventID)
            claimedTime = results.claimedTime
            contentResult = results.contentResult
            // We already verified this header previously
            headerResult = VerificationResult.VALID
            this.emit('syncContentResult', memberCID, results.contentResult)
        }

        let eventMetadata = this.eventMetadata.get(eventID)
        if (!eventMetadata) { // Is a new event
            if (headerResult !== VerificationResult.VALID
                || contentResult !== ContentVerificationResult.VALID) {
                // Either the header or the content for this event did not validate.
                // The event is invalid or the data is unavailable, and we have to skip it
                peer.lastIndex = i
                this.peers.set(memberCID, peer)
                // Decides whether to continue syncing the next events from this peer or stop
                const shouldContinue = this.onInvalidInput(memberCID, headerResult, contentResult)
                return shouldContinue
            }
            if (!claimedTime) {
                throw new Error("Invalid claimed time")
            }
            eventMetadata = {
                index: -1,
                received: -1,
                consensus: -1,
                claimed: claimedTime,
                membersReceived: new Map()
            }

            if (!initialSync) { // Event was received live, not from an initial peer sync
                const currentTime = getTimestampInSeconds()
                // If our peer's received time is close to our current time, use their time
                // This makes it harder to tell who first saw an event
                eventMetadata.received = (Math.abs(currentTime - entry.received) <= TOLERANCE)
                                                ? entry.received : currentTime

                // Need to set this before awaiting
                // Avoid concurrent addition of events
                this.eventMetadata.set(eventID, eventMetadata)
                const index = await this.publishReceived(eventID, eventMetadata.received)
                eventMetadata.index = index
                this.eventMetadata.set(eventID, eventMetadata)
            }

        } else if (eventMetadata.membersReceived.has(memberCID)) {
            return await this.onDuplicateInput(memberCID, eventID, i, peer.events.get(eventID))
        }

        // Add peer's received timestamp
        this.emit('syncEventReceivedTime', memberCID, eventID, entry.received)
        eventMetadata.membersReceived.set(memberCID, entry.received)
        this.eventMetadata.set(eventID, eventMetadata)

        peer.events.set(eventID, i)
        peer.lastIndex = i
        this.peers.set(memberCID, peer)
        await this.onMemberReceivedTime(eventID)

        return true
    }

    private async syncContent(
            memberCID: string,
            eventID: string,
            eventType?: string,
            contentHash?: string
            ): Promise<{
                contentResult: ContentVerificationResult,
                claimedTime?: number
            }> {
        let claimedTime
        // Retrieve info from header if not provided
        if (!eventType || !contentHash) {
            const eventHeaderBuf = await this.drive.get(`/events/${eventID}/header`)
            if (!eventHeaderBuf) {
                throw new Error("Missing header while trying to fetch content")
            }
            const eventHeader = deserializeEvent(eventHeaderBuf)
            eventType = eventHeader.eventType
            contentHash = eventHeader.contentHash
            claimedTime = eventHeader.claimed
        }
        const peer = this.peers.get(memberCID)
        if (!peer) {
            throw new Error("Unkown peer")
        }
        const entry = await peer.drive.entry(`/events/${eventID}/content`)
        if (!entry) {
            return { contentResult: ContentVerificationResult.UNAVAILABLE, claimedTime }
        }
        if (entry.value.blob.byteLength > this.maxContentSize.get(eventType)!) {
            return { contentResult: ContentVerificationResult.SIZE, claimedTime }
        }

        const contentBuf = await peer.drive.get(`/events/${eventID}/content`)
        if (!contentBuf) {
            return { contentResult: ContentVerificationResult.UNAVAILABLE, claimedTime }
        }
        if (contentBuf.length > this.maxContentSize.get(eventType)!) {
            return { contentResult: ContentVerificationResult.SIZE, claimedTime }
        }
        const hash = crypto.createHash('sha256').update(contentBuf).digest('hex')
        if (hash !== contentHash) {
            return { contentResult: ContentVerificationResult.HASH_MISMATCH, claimedTime }
        }

        if (!(await this.validateContent(eventID, eventType, contentBuf))){
            return { contentResult: ContentVerificationResult.INVALID, claimedTime }
        }

        await this.drive.put(`/events/${eventID}/content`, contentBuf)

        return { contentResult: ContentVerificationResult.VALID, claimedTime}
    }

    private async syncEvent(
        memberCID: string,
        eventID: string
        ): Promise<{
            headerResult: HeaderVerificationError | VerificationResult,
            contentResult?: ContentVerificationResult,
            claimedTime?: number
        }> {

        const peer = this.peers.get(memberCID)
        if (!peer) {
            throw new Error("Unkown peer")
        }
        const headerEntry = await peer.drive.entry(`/events/${eventID}/header`)
        if (!(headerEntry)) {
            // Header cannot be retrieved
            return { headerResult: HeaderVerificationError.UNAVAILABLE }
        }
        // TODO: Check header size before retrieving
        const eventHeaderBuf = await peer.drive.get(`/events/${eventID}/header`)
        if (!(eventHeaderBuf)) {
            return { headerResult: HeaderVerificationError.UNAVAILABLE }
        }

        const eventHeader = deserializeEvent(eventHeaderBuf)

        const headerResult = await this.addEvent(eventHeader)
        if (headerResult !== VerificationResult.VALID) {
            return { headerResult, claimedTime: eventHeader.claimed }
        }

        // If we can't fetch the content, or the content is invalid, we keep the header (which is already verified) saved
        // But we do not add the event anywhere else. We skip it later in the sync flow.
        // We will ignore the `received` for this event from this peer (and possibly ban the peer)
        // But if we find this event again on another peer we'll just try fetching the content again from them
        const { contentResult } = await this.syncContent(
                memberCID,
                eventID,
                eventHeader.eventType,
                eventHeader.contentHash)

        return { headerResult, contentResult, claimedTime: eventHeader.claimed }
    }

    protected async validateContent(eventID: string, eventType: string, buf: Buffer) {
        return true
    }

    private async publishReceived(eventID: string, received: number) {
        const eventMetadata = this.eventMetadata.get(eventID)
        if (eventMetadata && eventMetadata.index !== -1) {
            throw new Error("Trying to publish received time twice")
        }
        const {length, byteLength} = await this.core.append(serializeFeedEntry({
            eventID,
            received: received,
            oldestIndex: this.oldestIndex
        }))
        this.emit('publishReceivedTime', eventID, received)
        return length - 1
    }

    private calculateConsensusTime(timestamps: number[], totalPeers: number): number {
        if ((timestamps.length / totalPeers) < QUORUM) {
            // We do not have a quorum to decide on the correct time yet
            return -1
        }
        // Find the most common received time
        const [mostCommon, occurences] = mostCommonElement(timestamps)
        // If we have a ~2/3rds majority for one timestamp, use it
        if ((occurences / timestamps.length) >= QUORUM) {
            return mostCommon
        }
        // Fallback method: use mean timestamp

        // Filter out the timestamps that are more than one std.dev away from the mean
        const stdDev = getStandardDeviation(timestamps)
        const rawMean = getMean(timestamps)
        const filteredTimes = timestamps.filter(n => Math.abs(rawMean - n) <= stdDev)

        // If we still have more than one timestamp left, use these for the mean
        if (filteredTimes.length > 1) {
            return getMean(filteredTimes)
        }
        // Otherwise just return the regular mean
        return rawMean
    }

    /**
     * To be called whenever we add another peer's `received` time to an event
     * It recalculates our consensus timestamp and then acts appropriately
     * @param eventID The event's ID
     */
    private async onMemberReceivedTime(eventID: string) {
        const eventMetadata = this.eventMetadata.get(eventID)
        if (!eventMetadata) {
            throw new Error("Event not found")
        }
        const collectedTimestamps = Array.from(eventMetadata.membersReceived.values())
        // If we have a received time of our own
        if (eventMetadata.index !== -1) {
            // Add our contribution
            collectedTimestamps.push(eventMetadata.received)
        }
        const totalPeers = this.peers.size
            + (eventMetadata.index !== -1 ? 1 : 0) // Adding our own timestamp if it's been published
        const consensusTime = this.calculateConsensusTime(collectedTimestamps, totalPeers)

        if (consensusTime == -1) {
            return
        }

        if (eventMetadata.consensus !== consensusTime) {
            this.emit('consensusTimeChanged', eventID, eventMetadata.consensus, consensusTime)
            eventMetadata.consensus = consensusTime
            this.eventMetadata.set(eventID, eventMetadata)
        }

        // We have not yet published a received time
        if (eventMetadata.index == -1) {
            const index = await this.publishReceived(eventID, consensusTime)
            eventMetadata.received = consensusTime
            eventMetadata.index = index
            this.eventMetadata.set(eventID, eventMetadata)
        }

        // Message is determined to have been published at a false claimed time
        // if the consensus time differs too much from claimed time
        if (Math.abs(eventMetadata.claimed - consensusTime) > CLAIMED_TOLERANCE) {
            // Remove from timeline
            const prevTime = this.unsetTime(eventID)
            if (prevTime) {
                const roundedTime = Math.floor(prevTime / 1000)
                this.emit('timelineRemoveEvent', eventID, roundedTime, consensusTime)
            } else {
                this.emit('timelineRejectedEvent', eventID, eventMetadata.claimed, consensusTime)
            }
            return
        }

        const currentEventTime = this.eidTime.get(eventID)
        // Event is not in timeline yet
        if (!currentEventTime) {
            this.setTime(eventID, eventMetadata.claimed)
            this.emit('timelineAddEvent', eventID, eventMetadata.claimed, consensusTime)
        }
    }

    private getEventHash(event: FeedEventHeader) {
        return crypto.createHash('sha256')
            .update(event.eventType)
            .update(event.claimed.toString())
            .update(event.contentHash)
            .digest('hex')
    }

    private async verifyEvent(event: FeedEventHeader) {
        const proof = event.proof
        if (proof.rlnIdentifier !== this.topic) {
            return HeaderVerificationError.UNEXPECTED_RLN_IDENTIFIER
        }
        const specs = this.nullifierSpecs.get(event.eventType)
        if (!specs) {
            throw new Error("Unknown event type")
        }
        for (let i = 0; i < specs.length; i++) {
            if (proof.externalNullifiers[i].messageLimit
                !== specs[i].messageLimit) {
                return HeaderVerificationError.UNEXPECTED_MESSAGE_LIMIT
            }

            if (proof.externalNullifiers[i].nullifier
                !== `${getEpoch(specs[i].epoch, event.claimed)}|${event.eventType}`) {
                return HeaderVerificationError.UNEXPECTED_NULLIFIER
            }
        }
        return await this.rln.submitProof(proof, event.claimed)
    }

    private async addEvent(event: FeedEventHeader) {
        if (await this.drive.entry(`/events/${event.proof.signal}/header`)) {
            throw new Error("Event already added")
        }
        const eventID = this.getEventHash(event)
        if (event.proof.signal !== eventID) {
            return HeaderVerificationError.HASH_MISMATCH
        }
        const result = await this.verifyEvent(event)
        if (result !== VerificationResult.VALID) {
            return result
        }

        const eventBuf = serializeEvent(event)
        await this.drive.put(`/events/${eventID}/header`, eventBuf)
        return result
    }

    private createNullifier(eventType: string): nullifierInput[] {
        const specs = this.nullifierSpecs.get(eventType)
        if (!specs) {
            throw new Error("Unknown event type")
        }
        const nulls: nullifierInput[] = []
        for (let spec of specs) {
            nulls.push({
                nullifier: `${getEpoch(spec.epoch)}|${eventType}`,
                messageLimit: spec.messageLimit,
                messageId: 1
            })
        }
        return nulls
    }

    private async createEvent(
            eventType: string,
            nullifiers: nullifierInput[],
            content: Buffer
        ): Promise<[FeedEventHeader, string]> {
        const claimed = getTimestampInSeconds()
        const contentHash = crypto.createHash('sha256')
            .update(content)
            .digest('hex')

        const eventID = crypto.createHash('sha256')
            .update(eventType)
            .update(claimed.toString())
            .update(contentHash)
            .digest('hex')

        const proof = await this.rln.createProof(eventID, nullifiers, this.topic)
        return [{
            eventType,
            proof,
            claimed,
            contentHash
        },
        eventID]
    }

    public addEventType(eventType: string, specs: NullifierSpec[], maxContentSize: number) {
        this.nullifierSpecs.set(eventType, specs)
        this.maxContentSize.set(eventType, maxContentSize)
    }

    public async newEvent(eventType: string, content: Buffer) {
        const [event, eventID] = await this.createEvent(eventType, this.createNullifier(eventType), content)
        await this.drive.put(`/events/${eventID}/content`, content)
        const result = await this.addEvent(event)
        if (result == VerificationResult.VALID) {
            let eventMetadata = this.eventMetadata.get(eventID)
            if (eventMetadata) {
                throw new Error("Event already exists")
            }
            
            eventMetadata = {
                index: -1,
                received: event.claimed,
                consensus: -1,
                claimed: event.claimed,
                membersReceived: new Map()
            }
            this.eventMetadata.set(eventID, eventMetadata)
            const index = await this.publishReceived(eventID, event.claimed)
            eventMetadata.index = index
            this.eventMetadata.set(eventID, eventMetadata)
            this.setTime(eventID, event.claimed)
        }
        return result
    }

    public async getEventByID(eventID: string) {
        const eventHeaderBuf: Buffer = await this.drive.get(`/events/${eventID}/header`)
        const eventHeader: FeedEventHeader = deserializeEvent(eventHeaderBuf)
        const contentBuf: Buffer = await this.drive.get(`/events/${eventID}/content`)
        return {header: eventHeader, content: contentBuf}
    }

    public async getEvents(
        startTime: number = 0,
        endTime?: number,
        maxLength?: number
        ): Promise<{
            header: FeedEventHeader,
            content: Buffer
        }[]> {

        endTime = endTime || this.timeline.maxKey()
        if (!endTime) return []
        let returns = []
        for (let [time, eventID] of this.timeline.getRange(startTime, endTime, true, maxLength)) {
            const eventHeaderBuf: Buffer = await this.drive.get(`/events/${eventID}/header`)
            const eventHeader: FeedEventHeader = deserializeEvent(eventHeaderBuf)
            const contentBuf: Buffer = await this.drive.get(`/events/${eventID}/content`)
            returns.push({header: eventHeader, content: contentBuf})
        }
        return returns
    }
}