import { VerificationResult } from "@nabladelta/rln";
import { HeaderVerificationError, Lambdadelta } from "../lambdadelta";
import { RelayerNodeBase } from "./relayerNode";
import { createEvent } from "../create";

class RelayedLambdadelta extends Lambdadelta {
    private node: RelayerNodeBase<any> | undefined
    public setRelayer(node: RelayerNodeBase<any>) {
        this.node = node
    }
    public async newEvent(eventType: string, payload: Buffer): Promise<{ result: boolean; eventID: string; } | { result: VerificationResult | HeaderVerificationError; eventID: string; }> {
        if (!this.node) {
            return await super.newEvent(eventType, payload)
        }
        const nullifiers = await this.nullifierRegistry.createNullifier(eventType)
        const [eventHeader, eventID] = await createEvent(this.rln, this.topic, eventType, nullifiers, payload)
        const result = await this.node.relayEvent(this.topic, eventID, eventHeader, payload)
        return {result, eventID}
    }
}