// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Trail Sequence resource in Oracle Cloud Infrastructure Golden Gate service.
 *
 * Lists the Trail Sequences for a TrailFile in a given deployment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTrailSequence = oci.GoldenGate.getTrailSequence({
 *     deploymentId: testDeployment.id,
 *     trailFileId: testTrailFile.id,
 *     displayName: trailSequenceDisplayName,
 *     trailSequenceId: testTrailSequenceOciGoldenGateTrailSequence.id,
 * });
 * ```
 */
export function getTrailSequence(args: GetTrailSequenceArgs, opts?: pulumi.InvokeOptions): Promise<GetTrailSequenceResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:GoldenGate/getTrailSequence:getTrailSequence", {
        "deploymentId": args.deploymentId,
        "displayName": args.displayName,
        "trailFileId": args.trailFileId,
        "trailSequenceId": args.trailSequenceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getTrailSequence.
 */
export interface GetTrailSequenceArgs {
    /**
     * A unique Deployment identifier.
     */
    deploymentId: string;
    /**
     * A filter to return only the resources that match the entire 'displayName' given.
     */
    displayName: string;
    /**
     * A Trail File identifier
     */
    trailFileId: string;
    /**
     * A Trail Sequence identifier
     */
    trailSequenceId: string;
}

/**
 * A collection of values returned by getTrailSequence.
 */
export interface GetTrailSequenceResult {
    readonly deploymentId: string;
    /**
     * An object's Display Name.
     */
    readonly displayName: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * An array of TrailSequences.
     */
    readonly items: outputs.GoldenGate.GetTrailSequenceItem[];
    /**
     * The time the data was last fetched from the deployment. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     */
    readonly timeLastFetched: string;
    readonly trailFileId: string;
    readonly trailSequenceId: string;
}
/**
 * This data source provides details about a specific Trail Sequence resource in Oracle Cloud Infrastructure Golden Gate service.
 *
 * Lists the Trail Sequences for a TrailFile in a given deployment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTrailSequence = oci.GoldenGate.getTrailSequence({
 *     deploymentId: testDeployment.id,
 *     trailFileId: testTrailFile.id,
 *     displayName: trailSequenceDisplayName,
 *     trailSequenceId: testTrailSequenceOciGoldenGateTrailSequence.id,
 * });
 * ```
 */
export function getTrailSequenceOutput(args: GetTrailSequenceOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetTrailSequenceResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:GoldenGate/getTrailSequence:getTrailSequence", {
        "deploymentId": args.deploymentId,
        "displayName": args.displayName,
        "trailFileId": args.trailFileId,
        "trailSequenceId": args.trailSequenceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getTrailSequence.
 */
export interface GetTrailSequenceOutputArgs {
    /**
     * A unique Deployment identifier.
     */
    deploymentId: pulumi.Input<string>;
    /**
     * A filter to return only the resources that match the entire 'displayName' given.
     */
    displayName: pulumi.Input<string>;
    /**
     * A Trail File identifier
     */
    trailFileId: pulumi.Input<string>;
    /**
     * A Trail Sequence identifier
     */
    trailSequenceId: pulumi.Input<string>;
}
