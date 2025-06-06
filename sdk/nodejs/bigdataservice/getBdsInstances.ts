// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Bds Instances in Oracle Cloud Infrastructure Big Data Service service.
 *
 * Returns a list of all Big Data Service clusters in a compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBdsInstances = oci.BigDataService.getBdsInstances({
 *     compartmentId: compartmentId,
 *     displayName: bdsInstanceDisplayName,
 *     state: bdsInstanceState,
 * });
 * ```
 */
export function getBdsInstances(args: GetBdsInstancesArgs, opts?: pulumi.InvokeOptions): Promise<GetBdsInstancesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:BigDataService/getBdsInstances:getBdsInstances", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getBdsInstances.
 */
export interface GetBdsInstancesArgs {
    /**
     * The OCID of the compartment.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.BigDataService.GetBdsInstancesFilter[];
    /**
     * The state of the cluster.
     */
    state?: string;
}

/**
 * A collection of values returned by getBdsInstances.
 */
export interface GetBdsInstancesResult {
    /**
     * The list of bds_instances.
     */
    readonly bdsInstances: outputs.BigDataService.GetBdsInstancesBdsInstance[];
    /**
     * The OCID of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The name of the node.
     */
    readonly displayName?: string;
    readonly filters?: outputs.BigDataService.GetBdsInstancesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The state of the cluster.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Bds Instances in Oracle Cloud Infrastructure Big Data Service service.
 *
 * Returns a list of all Big Data Service clusters in a compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBdsInstances = oci.BigDataService.getBdsInstances({
 *     compartmentId: compartmentId,
 *     displayName: bdsInstanceDisplayName,
 *     state: bdsInstanceState,
 * });
 * ```
 */
export function getBdsInstancesOutput(args: GetBdsInstancesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetBdsInstancesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:BigDataService/getBdsInstances:getBdsInstances", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getBdsInstances.
 */
export interface GetBdsInstancesOutputArgs {
    /**
     * The OCID of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.BigDataService.GetBdsInstancesFilterArgs>[]>;
    /**
     * The state of the cluster.
     */
    state?: pulumi.Input<string>;
}
