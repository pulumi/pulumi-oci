// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Volumes in Oracle Cloud Infrastructure Core service.
 *
 * Lists the volumes in the specified compartment and availability domain.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVolumes = oci.Core.getVolumes({
 *     compartmentId: _var.compartment_id,
 *     availabilityDomain: _var.volume_availability_domain,
 *     displayName: _var.volume_display_name,
 *     state: _var.volume_state,
 *     volumeGroupId: oci_core_volume_group.test_volume_group.id,
 * });
 * ```
 */
export function getVolumes(args: GetVolumesArgs, opts?: pulumi.InvokeOptions): Promise<GetVolumesResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Core/getVolumes:getVolumes", {
        "availabilityDomain": args.availabilityDomain,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
        "volumeGroupId": args.volumeGroupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVolumes.
 */
export interface GetVolumesArgs {
    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.Core.GetVolumesFilter[];
    /**
     * A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: string;
    /**
     * The OCID of the volume group.
     */
    volumeGroupId?: string;
}

/**
 * A collection of values returned by getVolumes.
 */
export interface GetVolumesResult {
    /**
     * The availability domain of the block volume replica.  Example: `Uocm:PHX-AD-1`
     */
    readonly availabilityDomain?: string;
    /**
     * The OCID of the compartment that contains the volume.
     */
    readonly compartmentId: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Core.GetVolumesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of a volume.
     */
    readonly state?: string;
    /**
     * The OCID of the source volume group.
     */
    readonly volumeGroupId?: string;
    /**
     * The list of volumes.
     */
    readonly volumes: outputs.Core.GetVolumesVolume[];
}

export function getVolumesOutput(args: GetVolumesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetVolumesResult> {
    return pulumi.output(args).apply(a => getVolumes(a, opts))
}

/**
 * A collection of arguments for invoking getVolumes.
 */
export interface GetVolumesOutputArgs {
    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetVolumesFilterArgs>[]>;
    /**
     * A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: pulumi.Input<string>;
    /**
     * The OCID of the volume group.
     */
    volumeGroupId?: pulumi.Input<string>;
}
