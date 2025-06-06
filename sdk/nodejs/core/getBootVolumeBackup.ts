// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Boot Volume Backup resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets information for the specified boot volume backup.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBootVolumeBackup = oci.Core.getBootVolumeBackup({
 *     bootVolumeBackupId: testBootVolumeBackupOciCoreBootVolumeBackup.id,
 * });
 * ```
 */
export function getBootVolumeBackup(args: GetBootVolumeBackupArgs, opts?: pulumi.InvokeOptions): Promise<GetBootVolumeBackupResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Core/getBootVolumeBackup:getBootVolumeBackup", {
        "bootVolumeBackupId": args.bootVolumeBackupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBootVolumeBackup.
 */
export interface GetBootVolumeBackupArgs {
    /**
     * The OCID of the boot volume backup.
     */
    bootVolumeBackupId: string;
}

/**
 * A collection of values returned by getBootVolumeBackup.
 */
export interface GetBootVolumeBackupResult {
    readonly bootVolumeBackupId: string;
    /**
     * The OCID of the boot volume.
     */
    readonly bootVolumeId: string;
    /**
     * The OCID of the compartment that contains the boot volume backup.
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
     * The date and time the volume backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for backups that were created automatically by a scheduled-backup policy. For manually created backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
     */
    readonly expirationTime: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The OCID of the boot volume backup.
     */
    readonly id: string;
    /**
     * The image OCID used to create the boot volume the backup is taken from.
     */
    readonly imageId: string;
    /**
     * The OCID of the Vault service master encryption assigned to the boot volume backup. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
     */
    readonly kmsKeyId: string;
    /**
     * The size of the boot volume, in GBs.
     */
    readonly sizeInGbs: string;
    /**
     * The OCID of the source boot volume backup.
     */
    readonly sourceBootVolumeBackupId: string;
    readonly sourceDetails: outputs.Core.GetBootVolumeBackupSourceDetail[];
    /**
     * Specifies whether the backup was created manually, or via scheduled backup policy.
     */
    readonly sourceType: string;
    /**
     * The current state of a boot volume backup.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The date and time the boot volume backup was created. This is the time the actual point-in-time image of the volume data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeCreated: string;
    /**
     * The date and time the request to create the boot volume backup was received. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeRequestReceived: string;
    /**
     * The type of a volume backup. Supported values are 'FULL' or 'INCREMENTAL'.
     */
    readonly type: string;
    /**
     * The size used by the backup, in GBs. It is typically smaller than sizeInGBs, depending on the space consumed on the boot volume and whether the backup is full or incremental.
     */
    readonly uniqueSizeInGbs: string;
}
/**
 * This data source provides details about a specific Boot Volume Backup resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets information for the specified boot volume backup.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBootVolumeBackup = oci.Core.getBootVolumeBackup({
 *     bootVolumeBackupId: testBootVolumeBackupOciCoreBootVolumeBackup.id,
 * });
 * ```
 */
export function getBootVolumeBackupOutput(args: GetBootVolumeBackupOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetBootVolumeBackupResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Core/getBootVolumeBackup:getBootVolumeBackup", {
        "bootVolumeBackupId": args.bootVolumeBackupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBootVolumeBackup.
 */
export interface GetBootVolumeBackupOutputArgs {
    /**
     * The OCID of the boot volume backup.
     */
    bootVolumeBackupId: pulumi.Input<string>;
}
