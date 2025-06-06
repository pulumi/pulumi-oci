// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Stream resource in Oracle Cloud Infrastructure Streaming service.
 *
 * Gets detailed information about a stream, including the number of partitions.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testStream = oci.Streaming.getStream({
 *     streamId: testStreamOciStreamingStream.id,
 * });
 * ```
 */
export function getStream(args: GetStreamArgs, opts?: pulumi.InvokeOptions): Promise<GetStreamResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Streaming/getStream:getStream", {
        "streamId": args.streamId,
    }, opts);
}

/**
 * A collection of arguments for invoking getStream.
 */
export interface GetStreamArgs {
    /**
     * The OCID of the stream.
     */
    streamId: string;
}

/**
 * A collection of values returned by getStream.
 */
export interface GetStreamResult {
    /**
     * The OCID of the compartment that contains the stream.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations": {"CostCenter": "42"}}'
     */
    readonly definedTags: {[key: string]: string};
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The OCID of the stream.
     */
    readonly id: string;
    /**
     * Any additional details about the current state of the stream.
     */
    readonly lifecycleStateDetails: string;
    /**
     * The endpoint to use when creating the StreamClient to consume or publish messages in the stream. If the associated stream pool is private, the endpoint is also private and can only be accessed from inside the stream pool's associated subnet.
     */
    readonly messagesEndpoint: string;
    /**
     * The name of the stream. Avoid entering confidential information.  Example: `TelemetryEvents`
     */
    readonly name: string;
    /**
     * The number of partitions in the stream.
     */
    readonly partitions: number;
    /**
     * The retention period of the stream, in hours. This property is read-only.
     */
    readonly retentionInHours: number;
    /**
     * The current state of the stream.
     */
    readonly state: string;
    readonly streamId: string;
    /**
     * The OCID of the stream pool that contains the stream.
     */
    readonly streamPoolId: string;
    /**
     * The date and time the stream was created, expressed in in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2018-04-20T00:00:07.405Z`
     */
    readonly timeCreated: string;
}
/**
 * This data source provides details about a specific Stream resource in Oracle Cloud Infrastructure Streaming service.
 *
 * Gets detailed information about a stream, including the number of partitions.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testStream = oci.Streaming.getStream({
 *     streamId: testStreamOciStreamingStream.id,
 * });
 * ```
 */
export function getStreamOutput(args: GetStreamOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetStreamResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Streaming/getStream:getStream", {
        "streamId": args.streamId,
    }, opts);
}

/**
 * A collection of arguments for invoking getStream.
 */
export interface GetStreamOutputArgs {
    /**
     * The OCID of the stream.
     */
    streamId: pulumi.Input<string>;
}
