// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Snapshot resource in Oracle Cloud Infrastructure File Storage service.
 *
 * Gets the specified snapshot's information.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSnapshot = oci.FileStorage.getSnapshot({
 *     snapshotId: testSnapshotOciFileStorageSnapshot.id,
 * });
 * ```
 */
export function getSnapshot(args: GetSnapshotArgs, opts?: pulumi.InvokeOptions): Promise<GetSnapshotResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:FileStorage/getSnapshot:getSnapshot", {
        "snapshotId": args.snapshotId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSnapshot.
 */
export interface GetSnapshotArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the snapshot.
     */
    snapshotId: string;
}

/**
 * A collection of values returned by getSnapshot.
 */
export interface GetSnapshotResult {
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * The time when this snapshot will be deleted.
     */
    readonly expirationTime: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system from which the snapshot was created.
     */
    readonly fileSystemId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system snapshot policy that created this snapshot.
     */
    readonly filesystemSnapshotPolicyId: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the snapshot.
     */
    readonly id: string;
    /**
     * Specifies whether the snapshot has been cloned. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningFS.htm).
     */
    readonly isCloneSource: boolean;
    readonly isLockOverride: boolean;
    /**
     * Additional information about the current `lifecycleState`.
     */
    readonly lifecycleDetails: string;
    /**
     * Locks associated with this resource.
     */
    readonly locks: outputs.FileStorage.GetSnapshotLock[];
    /**
     * Name of the snapshot. This value is immutable.
     */
    readonly name: string;
    /**
     * An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) identifying the parent from which this snapshot was cloned. If this snapshot was not cloned, then the `provenanceId` is the same as the snapshot `id` value. If this snapshot was cloned, then the `provenanceId` value is the parent's `provenanceId`. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningFS.htm).
     */
    readonly provenanceId: string;
    readonly snapshotId: string;
    /**
     * The date and time the snapshot was taken, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format. This value might be the same or different from `timeCreated` depending on the following factors:
     * * If the snapshot is created in the original file system directory.
     * * If the snapshot is cloned from a file system.
     * * If the snapshot is replicated from a file system.
     */
    readonly snapshotTime: string;
    /**
     * Specifies the generation type of the snapshot.
     */
    readonly snapshotType: string;
    /**
     * The current state of the snapshot.
     */
    readonly state: string;
    /**
     * System tags for this resource. System tags are applied to resources by internal Oracle Cloud Infrastructure services.
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The date and time the snapshot was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeCreated: string;
}
/**
 * This data source provides details about a specific Snapshot resource in Oracle Cloud Infrastructure File Storage service.
 *
 * Gets the specified snapshot's information.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSnapshot = oci.FileStorage.getSnapshot({
 *     snapshotId: testSnapshotOciFileStorageSnapshot.id,
 * });
 * ```
 */
export function getSnapshotOutput(args: GetSnapshotOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSnapshotResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:FileStorage/getSnapshot:getSnapshot", {
        "snapshotId": args.snapshotId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSnapshot.
 */
export interface GetSnapshotOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the snapshot.
     */
    snapshotId: pulumi.Input<string>;
}
