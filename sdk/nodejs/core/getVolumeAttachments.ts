// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Volume Attachments in Oracle Cloud Infrastructure Core service.
 *
 * Lists the volume attachments in the specified compartment. You can filter the
 * list by specifying an instance OCID, volume OCID, or both.
 *
 * Currently, the only supported volume attachment type are [IScsiVolumeAttachment](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IScsiVolumeAttachment/) and
 * [ParavirtualizedVolumeAttachment](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/ParavirtualizedVolumeAttachment/).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVolumeAttachments = oci.Core.getVolumeAttachments({
 *     compartmentId: _var.compartment_id,
 *     availabilityDomain: _var.volume_attachment_availability_domain,
 *     instanceId: oci_core_instance.test_instance.id,
 *     volumeId: oci_core_volume.test_volume.id,
 * });
 * ```
 */
export function getVolumeAttachments(args: GetVolumeAttachmentsArgs, opts?: pulumi.InvokeOptions): Promise<GetVolumeAttachmentsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Core/getVolumeAttachments:getVolumeAttachments", {
        "availabilityDomain": args.availabilityDomain,
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "instanceId": args.instanceId,
        "volumeId": args.volumeId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVolumeAttachments.
 */
export interface GetVolumeAttachmentsArgs {
    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    filters?: inputs.Core.GetVolumeAttachmentsFilter[];
    /**
     * The OCID of the instance.
     */
    instanceId?: string;
    /**
     * The OCID of the volume.
     */
    volumeId?: string;
}

/**
 * A collection of values returned by getVolumeAttachments.
 */
export interface GetVolumeAttachmentsResult {
    /**
     * The availability domain of an instance.  Example: `Uocm:PHX-AD-1`
     */
    readonly availabilityDomain?: string;
    /**
     * The OCID of the compartment.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.Core.GetVolumeAttachmentsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The OCID of the instance the volume is attached to.
     */
    readonly instanceId?: string;
    /**
     * The list of volume_attachments.
     */
    readonly volumeAttachments: outputs.Core.GetVolumeAttachmentsVolumeAttachment[];
    /**
     * The OCID of the volume.
     */
    readonly volumeId?: string;
}

export function getVolumeAttachmentsOutput(args: GetVolumeAttachmentsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetVolumeAttachmentsResult> {
    return pulumi.output(args).apply(a => getVolumeAttachments(a, opts))
}

/**
 * A collection of arguments for invoking getVolumeAttachments.
 */
export interface GetVolumeAttachmentsOutputArgs {
    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetVolumeAttachmentsFilterArgs>[]>;
    /**
     * The OCID of the instance.
     */
    instanceId?: pulumi.Input<string>;
    /**
     * The OCID of the volume.
     */
    volumeId?: pulumi.Input<string>;
}