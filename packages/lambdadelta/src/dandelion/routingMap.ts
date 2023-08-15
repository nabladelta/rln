import { getRandomElement, getRandomIndex, getRandomInt, getTimestampInSeconds, isSubset } from "../utils"

export class RoutingMap {
    private maxDestinations: number
    private destinations: string[] = []
    private destinationMap: Map<string, number> = new Map()
    private nextRefresh: number
    private jitter: number
    private refreshInterval: number

    constructor(maxDestinations: number = 2, refreshInterval = 600, jitter = 100) {
        this.maxDestinations = maxDestinations
        this.nextRefresh = this.getNextRefreshTime()
        this.jitter = jitter
        this.refreshInterval = refreshInterval
    }

    /**
     * Get destination node corresponding to an inboundNode
     * @param inboundNode An inbound node
     * @returns the corresponding destination
     */
    public getDestination(inboundNode: string) {
        this.refreshMapping()
        const destId = this.destinationMap.get(inboundNode)
        if (destId === undefined) {
            return undefined
        }
        return this.destinations[destId]
    }

    /**
     * Update mappings with new peers
     * @param peers full list of peers
     */
    public updatePeers(peers: string[]) {
        this.updateDestinations(peers)
        if (peers.length == 0) {
            this.destinationMap = new Map()
            return
        }
        for (const peer of this.destinationMap.keys()) {
            // Peer no longer exists
            if (!peers.includes(peer)) {
                this.destinationMap.delete(peer)
            }
            // Destination is out of range
            if (this.destinationMap.get(peer)! > (this.destinations.length - 1)) {
                this.destinationMap.delete(peer)
            }
        }
        for (const peer of peers) {
            // Don't change already set peers
            if (this.destinationMap.get(peer) !== undefined) {
                continue
            }
            this.destinationMap.set(peer, getRandomIndex(this.destinations))
        }
    }

    private updateDestinations(peers: string[]) {
        if (peers.length == 0) {
            this.destinations = []
            return
        }
        // Check that the destinations are still in our peer list
        if (!isSubset(peers, this.destinations)) {
            this.destinations = []
        }
        if (this.destinations.length == this.maxDestinations) {
            return
        }
        if (this.destinations.length < this.maxDestinations) {
            // We can't get any more destinations
            if (this.destinations.length == peers.length) {
                return
            }
            this.destinations = []
        }
        // Don't modify original array
        peers = [...peers]
        // Select new destinations
        for (let i = 0; i < this.maxDestinations; i++) {
            const index = getRandomIndex(peers)
            this.destinations.push(peers[index])
            peers.splice(index, 1)
        }
    }

    /**
     * Re-Randomize mappings
     */
    private refreshMapping() {
        // Only refresh when time is due
        if (getTimestampInSeconds() < this.nextRefresh) {
            return
        }
        const peers = Array.from(this.destinationMap.keys())
        this.destinations = []
        this.destinationMap = new Map()
        this.updatePeers(peers)

        // Set next time for a refresh
        this.nextRefresh = this.getNextRefreshTime()
    }

    /**
     * Get the next time for a re-randomization of mappings
     * Should be `refreshInterval` +- a random value
     * @returns the next refresh time
     */
    private getNextRefreshTime() {
        return getTimestampInSeconds() + this.refreshInterval + getRandomInt(this.jitter) - (this.jitter/2)
    }
}