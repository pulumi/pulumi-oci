// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Channel resource in Oracle Cloud Infrastructure MySQL Database service.
 *
 * Gets the full details of the specified Channel, including the user-specified
 * configuration parameters (passwords are omitted), as well as information about
 * the state of the Channel, its sources and targets.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testChannel = oci.Mysql.getChannel({
 *     channelId: oci_mysql_channel.test_channel.id,
 * });
 * ```
 */
export function getChannel(args: GetChannelArgs, opts?: pulumi.InvokeOptions): Promise<GetChannelResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Mysql/getChannel:getChannel", {
        "channelId": args.channelId,
    }, opts);
}

/**
 * A collection of arguments for invoking getChannel.
 */
export interface GetChannelArgs {
    /**
     * The Channel [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    channelId: string;
}

/**
 * A collection of values returned by getChannel.
 */
export interface GetChannelResult {
    readonly channelId: string;
    /**
     * The OCID of the compartment.
     */
    readonly compartmentId: string;
    /**
     * Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * User provided description of the Channel.
     */
    readonly description: string;
    /**
     * The user-friendly name for the Channel. It does not have to be unique.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    readonly id: string;
    /**
     * Whether the Channel has been enabled by the user.
     */
    readonly isEnabled: boolean;
    /**
     * A message describing the state of the Channel.
     */
    readonly lifecycleDetails: string;
    /**
     * Parameters detailing how to provision the source for the given Channel.
     */
    readonly sources: outputs.Mysql.GetChannelSource[];
    /**
     * The state of the Channel.
     */
    readonly state: string;
    /**
     * Details about the Channel target.
     */
    readonly targets: outputs.Mysql.GetChannelTarget[];
    /**
     * The date and time the Channel was created, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     */
    readonly timeCreated: string;
    /**
     * The time the Channel was last updated, as described by [RFC 3339](https://tools.ietf.org/rfc/rfc3339).
     */
    readonly timeUpdated: string;
}

export function getChannelOutput(args: GetChannelOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetChannelResult> {
    return pulumi.output(args).apply(a => getChannel(a, opts))
}

/**
 * A collection of arguments for invoking getChannel.
 */
export interface GetChannelOutputArgs {
    /**
     * The Channel [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    channelId: pulumi.Input<string>;
}