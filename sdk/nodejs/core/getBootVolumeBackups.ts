// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Boot Volume Backups in Oracle Cloud Infrastructure Core service.
 *
 * Lists the boot volume backups in the specified compartment. You can filter the results by boot volume.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBootVolumeBackups = oci.Core.getBootVolumeBackups({
 *     compartmentId: _var.compartment_id,
 *     bootVolumeId: oci_core_boot_volume.test_boot_volume.id,
 *     displayName: _var.boot_volume_backup_display_name,
 *     sourceBootVolumeBackupId: oci_core_boot_volume_backup.test_boot_volume_backup.id,
 *     state: _var.boot_volume_backup_state,
 * });
 * ```
 */
export function getBootVolumeBackups(args: GetBootVolumeBackupsArgs, opts?: pulumi.InvokeOptions): Promise<GetBootVolumeBackupsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Core/getBootVolumeBackups:getBootVolumeBackups", {
        "bootVolumeId": args.bootVolumeId,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "sourceBootVolumeBackupId": args.sourceBootVolumeBackupId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getBootVolumeBackups.
 */
export interface GetBootVolumeBackupsArgs {
    /**
     * The OCID of the boot volume.
     */
    bootVolumeId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.Core.GetBootVolumeBackupsFilter[];
    /**
     * A filter to return only resources that originated from the given source boot volume backup.
     */
    sourceBootVolumeBackupId?: string;
    /**
     * A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: string;
}

/**
 * A collection of values returned by getBootVolumeBackups.
 */
export interface GetBootVolumeBackupsResult {
    /**
     * The list of boot_volume_backups.
     */
    readonly bootVolumeBackups: outputs.Core.GetBootVolumeBackupsBootVolumeBackup[];
    /**
     * The OCID of the boot volume.
     */
    readonly bootVolumeId?: string;
    /**
     * The OCID of the compartment that contains the boot volume backup.
     */
    readonly compartmentId: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Core.GetBootVolumeBackupsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The OCID of the source boot volume backup.
     */
    readonly sourceBootVolumeBackupId?: string;
    /**
     * The current state of a boot volume backup.
     */
    readonly state?: string;
}

export function getBootVolumeBackupsOutput(args: GetBootVolumeBackupsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetBootVolumeBackupsResult> {
    return pulumi.output(args).apply(a => getBootVolumeBackups(a, opts))
}

/**
 * A collection of arguments for invoking getBootVolumeBackups.
 */
export interface GetBootVolumeBackupsOutputArgs {
    /**
     * The OCID of the boot volume.
     */
    bootVolumeId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Core.GetBootVolumeBackupsFilterArgs>[]>;
    /**
     * A filter to return only resources that originated from the given source boot volume backup.
     */
    sourceBootVolumeBackupId?: pulumi.Input<string>;
    /**
     * A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: pulumi.Input<string>;
}