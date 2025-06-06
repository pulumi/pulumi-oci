// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Lustre File System resource in Oracle Cloud Infrastructure Lustre File Storage service.
 *
 * Creates a Lustre file system.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testLustreFileSystem = new oci.lustre.FileStorageLustreFileSystem("test_lustre_file_system", {
 *     availabilityDomain: lustreFileSystemAvailabilityDomain,
 *     capacityInGbs: lustreFileSystemCapacityInGbs,
 *     compartmentId: compartmentId,
 *     fileSystemName: testFileSystem.name,
 *     performanceTier: lustreFileSystemPerformanceTier,
 *     rootSquashConfiguration: {
 *         clientExceptions: lustreFileSystemRootSquashConfigurationClientExceptions,
 *         identitySquash: lustreFileSystemRootSquashConfigurationIdentitySquash,
 *         squashGid: lustreFileSystemRootSquashConfigurationSquashGid,
 *         squashUid: lustreFileSystemRootSquashConfigurationSquashUid,
 *     },
 *     subnetId: testSubnet.id,
 *     clusterPlacementGroupId: testClusterPlacementGroup.id,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: lustreFileSystemDisplayName,
 *     fileSystemDescription: lustreFileSystemFileSystemDescription,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     kmsKeyId: testKey.id,
 *     nsgIds: lustreFileSystemNsgIds,
 * });
 * ```
 *
 * ## Import
 *
 * LustreFileSystems can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Lustre/fileStorageLustreFileSystem:FileStorageLustreFileSystem test_lustre_file_system "id"
 * ```
 */
export class FileStorageLustreFileSystem extends pulumi.CustomResource {
    /**
     * Get an existing FileStorageLustreFileSystem resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: FileStorageLustreFileSystemState, opts?: pulumi.CustomResourceOptions): FileStorageLustreFileSystem {
        return new FileStorageLustreFileSystem(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Lustre/fileStorageLustreFileSystem:FileStorageLustreFileSystem';

    /**
     * Returns true if the given object is an instance of FileStorageLustreFileSystem.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is FileStorageLustreFileSystem {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === FileStorageLustreFileSystem.__pulumiType;
    }

    /**
     * The availability domain the file system is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
     */
    public readonly availabilityDomain!: pulumi.Output<string>;
    /**
     * (Updatable) Capacity of the Lustre file system in GB. You can increase capacity only in multiples of 5 TB.
     */
    public readonly capacityInGbs!: pulumi.Output<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group in which the Lustre file system exists.
     */
    public readonly clusterPlacementGroupId!: pulumi.Output<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the Lustre file system.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My Lustre file system`
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Short description of the Lustre file system. Avoid entering confidential information.
     */
    public readonly fileSystemDescription!: pulumi.Output<string>;
    /**
     * The Lustre file system name. This is used in mount commands and other aspects of the client command line interface. The file system name is limited to 8 characters. Allowed characters are lower and upper case English letters, numbers, and '_'. If you have multiple Lustre file systems mounted on the same clients, this name can help distinguish them.
     */
    public readonly fileSystemName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the KMS key used to encrypt the encryption keys associated with this file system.
     */
    public readonly kmsKeyId!: pulumi.Output<string>;
    /**
     * A message that describes the current state of the Lustre file system in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * Type of network used by clients to mount the file system.   Example: `tcp`
     */
    public /*out*/ readonly lnet!: pulumi.Output<string>;
    /**
     * The preferred day and time to perform maintenance.
     */
    public /*out*/ readonly maintenanceWindows!: pulumi.Output<outputs.Lustre.FileStorageLustreFileSystemMaintenanceWindow[]>;
    /**
     * Major version of Lustre running in the Lustre file system.  Example: `2.15`
     */
    public /*out*/ readonly majorVersion!: pulumi.Output<string>;
    /**
     * The IPv4 address of MGS (Lustre Management Service) used by clients to mount the file system. For example '10.0.0.4'.
     */
    public /*out*/ readonly managementServiceAddress!: pulumi.Output<string>;
    /**
     * (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this lustre file system. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the lustre file system from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
     */
    public readonly nsgIds!: pulumi.Output<string[]>;
    /**
     * The Lustre file system performance tier. A value of `MBPS_PER_TB_125` represents 125 megabytes per second per terabyte.
     */
    public readonly performanceTier!: pulumi.Output<string>;
    /**
     * (Updatable) An administrative feature that allows you to restrict root level access from clients that try to access your Lustre file system as root.
     */
    public readonly rootSquashConfiguration!: pulumi.Output<outputs.Lustre.FileStorageLustreFileSystemRootSquashConfiguration>;
    /**
     * The current state of the Lustre file system.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the Lustre file system is in.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly subnetId!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The date and time that the current billing cycle for the file system will end, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format. After the current cycle ends, this date is updated automatically to the next timestamp, which is 30 days later. File systems deleted earlier than this time will still incur charges until the billing cycle ends.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeBillingCycleEnd!: pulumi.Output<string>;
    /**
     * The date and time the Lustre file system was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2024-04-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the Lustre file system was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2024-04-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a FileStorageLustreFileSystem resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: FileStorageLustreFileSystemArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: FileStorageLustreFileSystemArgs | FileStorageLustreFileSystemState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as FileStorageLustreFileSystemState | undefined;
            resourceInputs["availabilityDomain"] = state ? state.availabilityDomain : undefined;
            resourceInputs["capacityInGbs"] = state ? state.capacityInGbs : undefined;
            resourceInputs["clusterPlacementGroupId"] = state ? state.clusterPlacementGroupId : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["fileSystemDescription"] = state ? state.fileSystemDescription : undefined;
            resourceInputs["fileSystemName"] = state ? state.fileSystemName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["kmsKeyId"] = state ? state.kmsKeyId : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["lnet"] = state ? state.lnet : undefined;
            resourceInputs["maintenanceWindows"] = state ? state.maintenanceWindows : undefined;
            resourceInputs["majorVersion"] = state ? state.majorVersion : undefined;
            resourceInputs["managementServiceAddress"] = state ? state.managementServiceAddress : undefined;
            resourceInputs["nsgIds"] = state ? state.nsgIds : undefined;
            resourceInputs["performanceTier"] = state ? state.performanceTier : undefined;
            resourceInputs["rootSquashConfiguration"] = state ? state.rootSquashConfiguration : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["subnetId"] = state ? state.subnetId : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeBillingCycleEnd"] = state ? state.timeBillingCycleEnd : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as FileStorageLustreFileSystemArgs | undefined;
            if ((!args || args.availabilityDomain === undefined) && !opts.urn) {
                throw new Error("Missing required property 'availabilityDomain'");
            }
            if ((!args || args.capacityInGbs === undefined) && !opts.urn) {
                throw new Error("Missing required property 'capacityInGbs'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.fileSystemName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'fileSystemName'");
            }
            if ((!args || args.performanceTier === undefined) && !opts.urn) {
                throw new Error("Missing required property 'performanceTier'");
            }
            if ((!args || args.rootSquashConfiguration === undefined) && !opts.urn) {
                throw new Error("Missing required property 'rootSquashConfiguration'");
            }
            if ((!args || args.subnetId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'subnetId'");
            }
            resourceInputs["availabilityDomain"] = args ? args.availabilityDomain : undefined;
            resourceInputs["capacityInGbs"] = args ? args.capacityInGbs : undefined;
            resourceInputs["clusterPlacementGroupId"] = args ? args.clusterPlacementGroupId : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["fileSystemDescription"] = args ? args.fileSystemDescription : undefined;
            resourceInputs["fileSystemName"] = args ? args.fileSystemName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["kmsKeyId"] = args ? args.kmsKeyId : undefined;
            resourceInputs["nsgIds"] = args ? args.nsgIds : undefined;
            resourceInputs["performanceTier"] = args ? args.performanceTier : undefined;
            resourceInputs["rootSquashConfiguration"] = args ? args.rootSquashConfiguration : undefined;
            resourceInputs["subnetId"] = args ? args.subnetId : undefined;
            resourceInputs["systemTags"] = args ? args.systemTags : undefined;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["lnet"] = undefined /*out*/;
            resourceInputs["maintenanceWindows"] = undefined /*out*/;
            resourceInputs["majorVersion"] = undefined /*out*/;
            resourceInputs["managementServiceAddress"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeBillingCycleEnd"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        const aliasOpts = { aliases: [{ type: "oci:oci/lustreFileStorageLustreFileSystem:LustreFileStorageLustreFileSystem" }] };
        opts = pulumi.mergeOptions(opts, aliasOpts);
        super(FileStorageLustreFileSystem.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering FileStorageLustreFileSystem resources.
 */
export interface FileStorageLustreFileSystemState {
    /**
     * The availability domain the file system is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * (Updatable) Capacity of the Lustre file system in GB. You can increase capacity only in multiples of 5 TB.
     */
    capacityInGbs?: pulumi.Input<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group in which the Lustre file system exists.
     */
    clusterPlacementGroupId?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the Lustre file system.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My Lustre file system`
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Short description of the Lustre file system. Avoid entering confidential information.
     */
    fileSystemDescription?: pulumi.Input<string>;
    /**
     * The Lustre file system name. This is used in mount commands and other aspects of the client command line interface. The file system name is limited to 8 characters. Allowed characters are lower and upper case English letters, numbers, and '_'. If you have multiple Lustre file systems mounted on the same clients, this name can help distinguish them.
     */
    fileSystemName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the KMS key used to encrypt the encryption keys associated with this file system.
     */
    kmsKeyId?: pulumi.Input<string>;
    /**
     * A message that describes the current state of the Lustre file system in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * Type of network used by clients to mount the file system.   Example: `tcp`
     */
    lnet?: pulumi.Input<string>;
    /**
     * The preferred day and time to perform maintenance.
     */
    maintenanceWindows?: pulumi.Input<pulumi.Input<inputs.Lustre.FileStorageLustreFileSystemMaintenanceWindow>[]>;
    /**
     * Major version of Lustre running in the Lustre file system.  Example: `2.15`
     */
    majorVersion?: pulumi.Input<string>;
    /**
     * The IPv4 address of MGS (Lustre Management Service) used by clients to mount the file system. For example '10.0.0.4'.
     */
    managementServiceAddress?: pulumi.Input<string>;
    /**
     * (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this lustre file system. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the lustre file system from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The Lustre file system performance tier. A value of `MBPS_PER_TB_125` represents 125 megabytes per second per terabyte.
     */
    performanceTier?: pulumi.Input<string>;
    /**
     * (Updatable) An administrative feature that allows you to restrict root level access from clients that try to access your Lustre file system as root.
     */
    rootSquashConfiguration?: pulumi.Input<inputs.Lustre.FileStorageLustreFileSystemRootSquashConfiguration>;
    /**
     * The current state of the Lustre file system.
     */
    state?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the Lustre file system is in.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    subnetId?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The date and time that the current billing cycle for the file system will end, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format. After the current cycle ends, this date is updated automatically to the next timestamp, which is 30 days later. File systems deleted earlier than this time will still incur charges until the billing cycle ends.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeBillingCycleEnd?: pulumi.Input<string>;
    /**
     * The date and time the Lustre file system was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2024-04-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the Lustre file system was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2024-04-25T21:10:29.600Z`
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a FileStorageLustreFileSystem resource.
 */
export interface FileStorageLustreFileSystemArgs {
    /**
     * The availability domain the file system is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain: pulumi.Input<string>;
    /**
     * (Updatable) Capacity of the Lustre file system in GB. You can increase capacity only in multiples of 5 TB.
     */
    capacityInGbs: pulumi.Input<number>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group in which the Lustre file system exists.
     */
    clusterPlacementGroupId?: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the Lustre file system.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My Lustre file system`
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Short description of the Lustre file system. Avoid entering confidential information.
     */
    fileSystemDescription?: pulumi.Input<string>;
    /**
     * The Lustre file system name. This is used in mount commands and other aspects of the client command line interface. The file system name is limited to 8 characters. Allowed characters are lower and upper case English letters, numbers, and '_'. If you have multiple Lustre file systems mounted on the same clients, this name can help distinguish them.
     */
    fileSystemName: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the KMS key used to encrypt the encryption keys associated with this file system.
     */
    kmsKeyId?: pulumi.Input<string>;
    /**
     * (Updatable) A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with this lustre file system. A maximum of 5 is allowed. Setting this to an empty array after the list is created removes the lustre file system from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm).
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The Lustre file system performance tier. A value of `MBPS_PER_TB_125` represents 125 megabytes per second per terabyte.
     */
    performanceTier: pulumi.Input<string>;
    /**
     * (Updatable) An administrative feature that allows you to restrict root level access from clients that try to access your Lustre file system as root.
     */
    rootSquashConfiguration: pulumi.Input<inputs.Lustre.FileStorageLustreFileSystemRootSquashConfiguration>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the Lustre file system is in.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    subnetId: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
}
