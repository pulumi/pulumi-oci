// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Block Volume Replicas in Oracle Cloud Infrastructure Core service.
 *
 * Lists the block volume replicas in the specified compartment and availability domain.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBlockVolumeReplicas = oci.Core.getBlockVolumeReplicas({
 *     availabilityDomain: _var.block_volume_replica_availability_domain,
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.block_volume_replica_display_name,
 *     state: _var.block_volume_replica_state,
 *     volumeGroupReplicaId: oci_core_volume_group_replica.test_volume_group_replica.id,
 * });
 * ```
 */
export function getBlockVolumeReplicas(args?: GetBlockVolumeReplicasArgs, opts?: pulumi.InvokeOptions): Promise<GetBlockVolumeReplicasResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Core/getBlockVolumeReplicas:getBlockVolumeReplicas", {
        "availabilityDomain": args.availabilityDomain,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
        "volumeGroupReplicaId": args.volumeGroupReplicaId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBlockVolumeReplicas.
 */
export interface GetBlockVolumeReplicasArgs {
    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.Core.GetBlockVolumeReplicasFilter[];
    /**
     * A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     */
    state?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the volume group replica.
     */
    volumeGroupReplicaId?: string;
}

/**
 * A collection of values returned by getBlockVolumeReplicas.
 */
export interface GetBlockVolumeReplicasResult {
    /**
     * The availability domain of the block volume replica.  Example: `Uocm:PHX-AD-1`
     */
    readonly availabilityDomain?: string;
    /**
     * The list of block_volume_replicas.
     */
    readonly blockVolumeReplicas: outputs.Core.GetBlockVolumeReplicasBlockVolumeReplica[];
    /**
     * The OCID of the compartment that contains the block volume replica.
     */
    readonly compartmentId?: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Core.GetBlockVolumeReplicasFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of a block volume replica.
     */
    readonly state?: string;
    readonly volumeGroupReplicaId?: string;
}

export function getBlockVolumeReplicasOutput(args?: GetBlockVolumeReplicasOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetBlockVolumeReplicasResult> {
    return pulumi.output(args).apply(a => getBlockVolumeReplicas(a, opts))
}

/**
 * A collection of arguments for invoking getBlockVolumeReplicas.
 */
export interface GetBlockVolumeReplicasOutputArgs {
    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetBlockVolumeReplicasFilterArgs>[]>;
    /**
     * A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     */
    state?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the volume group replica.
     */
    volumeGroupReplicaId?: pulumi.Input<string>;
}