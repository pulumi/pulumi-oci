// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Cluster Network Instances in Oracle Cloud Infrastructure Core service.
 *
 * Lists the instances in the specified cluster network.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testClusterNetworkInstances = oci.Core.getClusterNetworkInstances({
 *     clusterNetworkId: oci_core_cluster_network.test_cluster_network.id,
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.cluster_network_instance_display_name,
 * });
 * ```
 */
export function getClusterNetworkInstances(args: GetClusterNetworkInstancesArgs, opts?: pulumi.InvokeOptions): Promise<GetClusterNetworkInstancesResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Core/getClusterNetworkInstances:getClusterNetworkInstances", {
        "clusterNetworkId": args.clusterNetworkId,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getClusterNetworkInstances.
 */
export interface GetClusterNetworkInstancesArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster network.
     */
    clusterNetworkId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.Core.GetClusterNetworkInstancesFilter[];
}

/**
 * A collection of values returned by getClusterNetworkInstances.
 */
export interface GetClusterNetworkInstancesResult {
    readonly clusterNetworkId: string;
    /**
     * The OCID of the compartment that contains the instance.
     */
    readonly compartmentId: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Core.GetClusterNetworkInstancesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of instances.
     */
    readonly instances: outputs.Core.GetClusterNetworkInstancesInstance[];
}

export function getClusterNetworkInstancesOutput(args: GetClusterNetworkInstancesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetClusterNetworkInstancesResult> {
    return pulumi.output(args).apply(a => getClusterNetworkInstances(a, opts))
}

/**
 * A collection of arguments for invoking getClusterNetworkInstances.
 */
export interface GetClusterNetworkInstancesOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster network.
     */
    clusterNetworkId: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetClusterNetworkInstancesFilterArgs>[]>;
}