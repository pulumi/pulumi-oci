// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Awr Hub resource in Oracle Cloud Infrastructure Opsi service.
 *
 * Gets details of an AWR hub.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAwrHub = oci.Opsi.getAwrHub({
 *     awrHubId: oci_opsi_awr_hub.test_awr_hub.id,
 * });
 * ```
 */
export function getAwrHub(args: GetAwrHubArgs, opts?: pulumi.InvokeOptions): Promise<GetAwrHubResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Opsi/getAwrHub:getAwrHub", {
        "awrHubId": args.awrHubId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAwrHub.
 */
export interface GetAwrHubArgs {
    /**
     * Unique Awr Hub identifier
     */
    awrHubId: string;
}

/**
 * A collection of values returned by getAwrHub.
 */
export interface GetAwrHubResult {
    readonly awrHubId: string;
    /**
     * Mailbox URL required for AWR hub and AWR source setup.
     */
    readonly awrMailboxUrl: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * User-friedly name of AWR Hub that does not have to be unique.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * AWR Hub OCID
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * Object Storage Bucket Name
     */
    readonly objectStorageBucketName: string;
    /**
     * OPSI Warehouse OCID
     */
    readonly operationsInsightsWarehouseId: string;
    /**
     * Possible lifecycle states
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The time at which the resource was first created. An RFC3339 formatted datetime string
     */
    readonly timeCreated: string;
    /**
     * The time at which the resource was last updated. An RFC3339 formatted datetime string
     */
    readonly timeUpdated: string;
}

export function getAwrHubOutput(args: GetAwrHubOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetAwrHubResult> {
    return pulumi.output(args).apply(a => getAwrHub(a, opts))
}

/**
 * A collection of arguments for invoking getAwrHub.
 */
export interface GetAwrHubOutputArgs {
    /**
     * Unique Awr Hub identifier
     */
    awrHubId: pulumi.Input<string>;
}