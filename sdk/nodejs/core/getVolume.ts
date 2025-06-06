// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Volume resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets information for the specified volume.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVolume = oci.Core.getVolume({
 *     volumeId: testVolumeOciCoreVolume.id,
 * });
 * ```
 */
export function getVolume(args: GetVolumeArgs, opts?: pulumi.InvokeOptions): Promise<GetVolumeResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Core/getVolume:getVolume", {
        "volumeId": args.volumeId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVolume.
 */
export interface GetVolumeArgs {
    /**
     * The OCID of the volume.
     */
    volumeId: string;
}

/**
 * A collection of values returned by getVolume.
 */
export interface GetVolumeResult {
    /**
     * The number of Volume Performance Units per GB that this volume is effectively tuned to.
     */
    readonly autoTunedVpusPerGb: string;
    /**
     * The list of autotune policies enabled for this volume.
     */
    readonly autotunePolicies: outputs.Core.GetVolumeAutotunePolicy[];
    /**
     * The availability domain of the block volume replica.  Example: `Uocm:PHX-AD-1`
     */
    readonly availabilityDomain: string;
    /**
     * @deprecated The 'backup_policy_id' field has been deprecated. Please use the 'oci_core_volume_backup_policy_assignment' resource instead.
     */
    readonly backupPolicyId: string;
    /**
     * The list of block volume replicas of this volume.
     */
    readonly blockVolumeReplicas: outputs.Core.GetVolumeBlockVolumeReplica[];
    readonly blockVolumeReplicasDeletion: boolean;
    /**
     * The clusterPlacementGroup Id of the volume for volume placement.
     */
    readonly clusterPlacementGroupId: string;
    /**
     * The OCID of the compartment that contains the volume.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * (Required when type=blockVolumeReplica | volume | volumeBackup) The OCID of the block volume replica.
     */
    readonly id: string;
    /**
     * Specifies whether the auto-tune performance is enabled for this volume. This field is deprecated. Use the `DetachedVolumeAutotunePolicy` instead to enable the volume for detached autotune.
     */
    readonly isAutoTuneEnabled: boolean;
    /**
     * Specifies whether the cloned volume's data has finished copying from the source volume or backup.
     */
    readonly isHydrated: boolean;
    /**
     * Reservations-enabled is a boolean field that allows to enable PR (Persistent Reservation) on a volume.
     */
    readonly isReservationsEnabled: boolean;
    /**
     * The OCID of the Vault service key which is the master encryption key for the volume.
     */
    readonly kmsKeyId: string;
    /**
     * The size of the volume in GBs.
     */
    readonly sizeInGbs: string;
    /**
     * The size of the volume in MBs. This field is deprecated. Use sizeInGBs instead.
     *
     * @deprecated The 'size_in_mbs' field has been deprecated. Please use 'size_in_gbs' instead.
     */
    readonly sizeInMbs: string;
    /**
     * Specifies the volume source details for a new Block volume. The volume source is either another Block volume in the same Availability Domain or a Block volume backup. This is an optional field. If not specified or set to null, the new Block volume will be empty. When specified, the new Block volume will contain data from the source volume or backup.
     */
    readonly sourceDetails: outputs.Core.GetVolumeSourceDetail[];
    /**
     * The current state of a volume.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The date and time the volume was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeCreated: string;
    readonly volumeBackupId: string;
    /**
     * The OCID of the source volume group.
     */
    readonly volumeGroupId: string;
    readonly volumeId: string;
    /**
     * The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service's elastic performance options. See [Block Volume Performance Levels](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeperformance.htm#perf_levels) for more information.
     */
    readonly vpusPerGb: string;
    readonly xrcKmsKeyId: string;
}
/**
 * This data source provides details about a specific Volume resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets information for the specified volume.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVolume = oci.Core.getVolume({
 *     volumeId: testVolumeOciCoreVolume.id,
 * });
 * ```
 */
export function getVolumeOutput(args: GetVolumeOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetVolumeResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Core/getVolume:getVolume", {
        "volumeId": args.volumeId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVolume.
 */
export interface GetVolumeOutputArgs {
    /**
     * The OCID of the volume.
     */
    volumeId: pulumi.Input<string>;
}
