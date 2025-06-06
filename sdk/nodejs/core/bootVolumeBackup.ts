// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Boot Volume Backup resource in Oracle Cloud Infrastructure Core service.
 *
 * Creates a new boot volume backup of the specified boot volume. For general information about boot volume backups,
 * see [Overview of Boot Volume Backups](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/bootvolumebackups.htm)
 *
 * When the request is received, the backup object is in a REQUEST_RECEIVED state.
 * When the data is imaged, it goes into a CREATING state.
 * After the backup is fully uploaded to the cloud, it goes into an AVAILABLE state.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBootVolumeBackup = new oci.core.BootVolumeBackup("test_boot_volume_backup", {
 *     bootVolumeId: testBootVolume.id,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: bootVolumeBackupDisplayName,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     kmsKeyId: testKey.id,
 *     type: bootVolumeBackupType,
 * });
 * ```
 *
 * ## Import
 *
 * BootVolumeBackups can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Core/bootVolumeBackup:BootVolumeBackup test_boot_volume_backup "id"
 * ```
 */
export class BootVolumeBackup extends pulumi.CustomResource {
    /**
     * Get an existing BootVolumeBackup resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: BootVolumeBackupState, opts?: pulumi.CustomResourceOptions): BootVolumeBackup {
        return new BootVolumeBackup(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Core/bootVolumeBackup:BootVolumeBackup';

    /**
     * Returns true if the given object is an instance of BootVolumeBackup.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is BootVolumeBackup {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === BootVolumeBackup.__pulumiType;
    }

    /**
     * The OCID of the boot volume that needs to be backed up. Cannot be defined if `sourceDetails` is defined.
     */
    public readonly bootVolumeId!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the compartment that contains the boot volume backup.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The date and time the volume backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for backups that were created automatically by a scheduled-backup policy. For manually created backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
     */
    public /*out*/ readonly expirationTime!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The image OCID used to create the boot volume the backup is taken from.
     */
    public /*out*/ readonly imageId!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the Vault service key which is the master encryption key for the volume backup. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
     */
    public readonly kmsKeyId!: pulumi.Output<string>;
    /**
     * The size of the boot volume, in GBs.
     */
    public /*out*/ readonly sizeInGbs!: pulumi.Output<string>;
    /**
     * The OCID of the source boot volume backup.
     */
    public /*out*/ readonly sourceBootVolumeBackupId!: pulumi.Output<string>;
    /**
     * Details of the volume backup source in the cloud. Cannot be defined if `bootVolumeId` is defined.
     */
    public readonly sourceDetails!: pulumi.Output<outputs.Core.BootVolumeBackupSourceDetails | undefined>;
    /**
     * Specifies whether the backup was created manually, or via scheduled backup policy.
     */
    public /*out*/ readonly sourceType!: pulumi.Output<string>;
    /**
     * The current state of a boot volume backup.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The date and time the boot volume backup was created. This is the time the actual point-in-time image of the volume data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the request to create the boot volume backup was received. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    public /*out*/ readonly timeRequestReceived!: pulumi.Output<string>;
    /**
     * The type of backup to create. If omitted, defaults to incremental. Supported values are 'FULL' or 'INCREMENTAL'.
     */
    public readonly type!: pulumi.Output<string>;
    /**
     * The size used by the backup, in GBs. It is typically smaller than sizeInGBs, depending on the space consumed on the boot volume and whether the backup is full or incremental.
     */
    public /*out*/ readonly uniqueSizeInGbs!: pulumi.Output<string>;

    /**
     * Create a BootVolumeBackup resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args?: BootVolumeBackupArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: BootVolumeBackupArgs | BootVolumeBackupState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as BootVolumeBackupState | undefined;
            resourceInputs["bootVolumeId"] = state ? state.bootVolumeId : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["expirationTime"] = state ? state.expirationTime : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["imageId"] = state ? state.imageId : undefined;
            resourceInputs["kmsKeyId"] = state ? state.kmsKeyId : undefined;
            resourceInputs["sizeInGbs"] = state ? state.sizeInGbs : undefined;
            resourceInputs["sourceBootVolumeBackupId"] = state ? state.sourceBootVolumeBackupId : undefined;
            resourceInputs["sourceDetails"] = state ? state.sourceDetails : undefined;
            resourceInputs["sourceType"] = state ? state.sourceType : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeRequestReceived"] = state ? state.timeRequestReceived : undefined;
            resourceInputs["type"] = state ? state.type : undefined;
            resourceInputs["uniqueSizeInGbs"] = state ? state.uniqueSizeInGbs : undefined;
        } else {
            const args = argsOrState as BootVolumeBackupArgs | undefined;
            resourceInputs["bootVolumeId"] = args ? args.bootVolumeId : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["kmsKeyId"] = args ? args.kmsKeyId : undefined;
            resourceInputs["sourceDetails"] = args ? args.sourceDetails : undefined;
            resourceInputs["type"] = args ? args.type : undefined;
            resourceInputs["expirationTime"] = undefined /*out*/;
            resourceInputs["imageId"] = undefined /*out*/;
            resourceInputs["sizeInGbs"] = undefined /*out*/;
            resourceInputs["sourceBootVolumeBackupId"] = undefined /*out*/;
            resourceInputs["sourceType"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeRequestReceived"] = undefined /*out*/;
            resourceInputs["uniqueSizeInGbs"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(BootVolumeBackup.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering BootVolumeBackup resources.
 */
export interface BootVolumeBackupState {
    /**
     * The OCID of the boot volume that needs to be backed up. Cannot be defined if `sourceDetails` is defined.
     */
    bootVolumeId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the compartment that contains the boot volume backup.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The date and time the volume backup will expire and be automatically deleted. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). This parameter will always be present for backups that were created automatically by a scheduled-backup policy. For manually created backups, it will be absent, signifying that there is no expiration time and the backup will last forever until manually deleted.
     */
    expirationTime?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The image OCID used to create the boot volume the backup is taken from.
     */
    imageId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the Vault service key which is the master encryption key for the volume backup. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
     */
    kmsKeyId?: pulumi.Input<string>;
    /**
     * The size of the boot volume, in GBs.
     */
    sizeInGbs?: pulumi.Input<string>;
    /**
     * The OCID of the source boot volume backup.
     */
    sourceBootVolumeBackupId?: pulumi.Input<string>;
    /**
     * Details of the volume backup source in the cloud. Cannot be defined if `bootVolumeId` is defined.
     */
    sourceDetails?: pulumi.Input<inputs.Core.BootVolumeBackupSourceDetails>;
    /**
     * Specifies whether the backup was created manually, or via scheduled backup policy.
     */
    sourceType?: pulumi.Input<string>;
    /**
     * The current state of a boot volume backup.
     */
    state?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The date and time the boot volume backup was created. This is the time the actual point-in-time image of the volume data was taken. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the request to create the boot volume backup was received. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    timeRequestReceived?: pulumi.Input<string>;
    /**
     * The type of backup to create. If omitted, defaults to incremental. Supported values are 'FULL' or 'INCREMENTAL'.
     */
    type?: pulumi.Input<string>;
    /**
     * The size used by the backup, in GBs. It is typically smaller than sizeInGBs, depending on the space consumed on the boot volume and whether the backup is full or incremental.
     */
    uniqueSizeInGbs?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a BootVolumeBackup resource.
 */
export interface BootVolumeBackupArgs {
    /**
     * The OCID of the boot volume that needs to be backed up. Cannot be defined if `sourceDetails` is defined.
     */
    bootVolumeId?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the compartment that contains the boot volume backup.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The OCID of the Vault service key which is the master encryption key for the volume backup. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
     */
    kmsKeyId?: pulumi.Input<string>;
    /**
     * Details of the volume backup source in the cloud. Cannot be defined if `bootVolumeId` is defined.
     */
    sourceDetails?: pulumi.Input<inputs.Core.BootVolumeBackupSourceDetails>;
    /**
     * The type of backup to create. If omitted, defaults to incremental. Supported values are 'FULL' or 'INCREMENTAL'.
     */
    type?: pulumi.Input<string>;
}
