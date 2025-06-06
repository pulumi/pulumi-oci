// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Vm Cluster Add Virtual Machine resource in Oracle Cloud Infrastructure Database service.
 *
 * Add Virtual Machines to the VM cluster. Applies to Exadata Cloud@Customer instances only.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVmClusterAddVirtualMachine = new oci.database.VmClusterAddVirtualNetwork("test_vm_cluster_add_virtual_machine", {
 *     dbServers: [{
 *         dbServerId: testDbServer.id,
 *     }],
 *     vmClusterId: testVmCluster.id,
 * });
 * ```
 *
 * ##### Note: You may also need to add `dbServers` and `cpuCoreCount` to the ignoreChanges for the resource `oci.Database.VmCluster` list if you see a diff on a subsequent apply
 *
 * ## Import
 *
 * VmClusterAddVirtualMachine can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Database/vmClusterAddVirtualNetwork:VmClusterAddVirtualNetwork test_vm_cluster_add_virtual_machine "id"
 * ```
 */
export class VmClusterAddVirtualNetwork extends pulumi.CustomResource {
    /**
     * Get an existing VmClusterAddVirtualNetwork resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: VmClusterAddVirtualNetworkState, opts?: pulumi.CustomResourceOptions): VmClusterAddVirtualNetwork {
        return new VmClusterAddVirtualNetwork(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Database/vmClusterAddVirtualNetwork:VmClusterAddVirtualNetwork';

    /**
     * Returns true if the given object is an instance of VmClusterAddVirtualNetwork.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is VmClusterAddVirtualNetwork {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === VmClusterAddVirtualNetwork.__pulumiType;
    }

    /**
     * The name of the availability domain that the VM cluster is located in.
     */
    public /*out*/ readonly availabilityDomain!: pulumi.Output<string>;
    /**
     * Specifies the properties necessary for cloud automation updates. This includes modifying the apply update time preference, enabling or disabling early adoption, and enabling, modifying, or disabling the update freeze period.
     */
    public /*out*/ readonly cloudAutomationUpdateDetails!: pulumi.Output<outputs.Database.VmClusterAddVirtualNetworkCloudAutomationUpdateDetail[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * The compute model of the Autonomous Database. This is required if using the `computeCount` parameter. If using `cpuCoreCount` then it is an error to specify `computeModel` to a non-null value. ECPU compute model is the recommended model and OCPU compute model is legacy.
     */
    public /*out*/ readonly computeModel!: pulumi.Output<string>;
    /**
     * The number of enabled CPU cores.
     */
    public /*out*/ readonly cpusEnabled!: pulumi.Output<number>;
    /**
     * Indicates user preferences for the various diagnostic collection options for the VM cluster/Cloud VM cluster/VMBM DBCS.
     */
    public /*out*/ readonly dataCollectionOptions!: pulumi.Output<outputs.Database.VmClusterAddVirtualNetworkDataCollectionOption[]>;
    /**
     * Size of the DATA disk group in GBs.
     */
    public /*out*/ readonly dataStorageSizeInGb!: pulumi.Output<number>;
    /**
     * Size, in terabytes, of the DATA disk group.
     */
    public /*out*/ readonly dataStorageSizeInTbs!: pulumi.Output<number>;
    /**
     * The local node storage allocated in GBs.
     */
    public /*out*/ readonly dbNodeStorageSizeInGbs!: pulumi.Output<number>;
    /**
     * The list of Exacc DB servers for the cluster to be added.
     */
    public readonly dbServers!: pulumi.Output<outputs.Database.VmClusterAddVirtualNetworkDbServer[]>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public /*out*/ readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The user-friendly name for the Exadata Cloud@Customer VM cluster. The name does not need to be unique.
     */
    public /*out*/ readonly displayName!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     */
    public /*out*/ readonly exadataInfrastructureId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata Database Storage Vault.
     */
    public /*out*/ readonly exascaleDbStorageVaultId!: pulumi.Output<string>;
    /**
     * Details of the file system configuration of the VM cluster.
     */
    public /*out*/ readonly fileSystemConfigurationDetails!: pulumi.Output<outputs.Database.VmClusterAddVirtualNetworkFileSystemConfigurationDetail[]>;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public /*out*/ readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The Oracle Grid Infrastructure software version for the VM cluster.
     */
    public /*out*/ readonly giVersion!: pulumi.Output<string>;
    /**
     * If true, database backup on local Exadata storage is configured for the VM cluster. If false, database backup on local Exadata storage is not available in the VM cluster.
     */
    public /*out*/ readonly isLocalBackupEnabled!: pulumi.Output<boolean>;
    /**
     * If true, sparse disk group is configured for the VM cluster. If false, sparse disk group is not created.
     */
    public /*out*/ readonly isSparseDiskgroupEnabled!: pulumi.Output<boolean>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch history. This value is updated as soon as a patch operation starts.
     */
    public /*out*/ readonly lastPatchHistoryEntryId!: pulumi.Output<string>;
    /**
     * The Oracle license model that applies to the VM cluster. The default is LICENSE_INCLUDED.
     */
    public /*out*/ readonly licenseModel!: pulumi.Output<string>;
    /**
     * Additional information about the current lifecycle state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The memory allocated in GBs.
     */
    public /*out*/ readonly memorySizeInGbs!: pulumi.Output<number>;
    public /*out*/ readonly ocpusEnabled!: pulumi.Output<number>;
    /**
     * The shape of the Exadata infrastructure. The shape determines the amount of CPU, storage, and memory resources allocated to the instance.
     */
    public /*out*/ readonly shape!: pulumi.Output<string>;
    /**
     * The public key portion of one or more key pairs used for SSH access to the VM cluster.
     */
    public /*out*/ readonly sshPublicKeys!: pulumi.Output<string[]>;
    /**
     * The current state of the VM cluster.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Specifies whether the type of storage management for the VM cluster is ASM or Exascale.
     */
    public /*out*/ readonly storageManagementType!: pulumi.Output<string>;
    /**
     * Operating system version of the image.
     */
    public /*out*/ readonly systemVersion!: pulumi.Output<string>;
    /**
     * The date and time that the VM cluster was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time zone of the Exadata infrastructure. For details, see [Exadata Infrastructure Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
     */
    public /*out*/ readonly timeZone!: pulumi.Output<string>;
    /**
     * The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly vmClusterId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
     */
    public /*out*/ readonly vmClusterNetworkId!: pulumi.Output<string>;
    /**
     * The vmcluster type for the VM cluster/Cloud VM cluster.
     */
    public /*out*/ readonly vmClusterType!: pulumi.Output<string>;

    /**
     * Create a VmClusterAddVirtualNetwork resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: VmClusterAddVirtualNetworkArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: VmClusterAddVirtualNetworkArgs | VmClusterAddVirtualNetworkState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as VmClusterAddVirtualNetworkState | undefined;
            resourceInputs["availabilityDomain"] = state ? state.availabilityDomain : undefined;
            resourceInputs["cloudAutomationUpdateDetails"] = state ? state.cloudAutomationUpdateDetails : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["computeModel"] = state ? state.computeModel : undefined;
            resourceInputs["cpusEnabled"] = state ? state.cpusEnabled : undefined;
            resourceInputs["dataCollectionOptions"] = state ? state.dataCollectionOptions : undefined;
            resourceInputs["dataStorageSizeInGb"] = state ? state.dataStorageSizeInGb : undefined;
            resourceInputs["dataStorageSizeInTbs"] = state ? state.dataStorageSizeInTbs : undefined;
            resourceInputs["dbNodeStorageSizeInGbs"] = state ? state.dbNodeStorageSizeInGbs : undefined;
            resourceInputs["dbServers"] = state ? state.dbServers : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["exadataInfrastructureId"] = state ? state.exadataInfrastructureId : undefined;
            resourceInputs["exascaleDbStorageVaultId"] = state ? state.exascaleDbStorageVaultId : undefined;
            resourceInputs["fileSystemConfigurationDetails"] = state ? state.fileSystemConfigurationDetails : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["giVersion"] = state ? state.giVersion : undefined;
            resourceInputs["isLocalBackupEnabled"] = state ? state.isLocalBackupEnabled : undefined;
            resourceInputs["isSparseDiskgroupEnabled"] = state ? state.isSparseDiskgroupEnabled : undefined;
            resourceInputs["lastPatchHistoryEntryId"] = state ? state.lastPatchHistoryEntryId : undefined;
            resourceInputs["licenseModel"] = state ? state.licenseModel : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["memorySizeInGbs"] = state ? state.memorySizeInGbs : undefined;
            resourceInputs["ocpusEnabled"] = state ? state.ocpusEnabled : undefined;
            resourceInputs["shape"] = state ? state.shape : undefined;
            resourceInputs["sshPublicKeys"] = state ? state.sshPublicKeys : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["storageManagementType"] = state ? state.storageManagementType : undefined;
            resourceInputs["systemVersion"] = state ? state.systemVersion : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeZone"] = state ? state.timeZone : undefined;
            resourceInputs["vmClusterId"] = state ? state.vmClusterId : undefined;
            resourceInputs["vmClusterNetworkId"] = state ? state.vmClusterNetworkId : undefined;
            resourceInputs["vmClusterType"] = state ? state.vmClusterType : undefined;
        } else {
            const args = argsOrState as VmClusterAddVirtualNetworkArgs | undefined;
            if ((!args || args.dbServers === undefined) && !opts.urn) {
                throw new Error("Missing required property 'dbServers'");
            }
            if ((!args || args.vmClusterId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'vmClusterId'");
            }
            resourceInputs["dbServers"] = args ? args.dbServers : undefined;
            resourceInputs["vmClusterId"] = args ? args.vmClusterId : undefined;
            resourceInputs["availabilityDomain"] = undefined /*out*/;
            resourceInputs["cloudAutomationUpdateDetails"] = undefined /*out*/;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["computeModel"] = undefined /*out*/;
            resourceInputs["cpusEnabled"] = undefined /*out*/;
            resourceInputs["dataCollectionOptions"] = undefined /*out*/;
            resourceInputs["dataStorageSizeInGb"] = undefined /*out*/;
            resourceInputs["dataStorageSizeInTbs"] = undefined /*out*/;
            resourceInputs["dbNodeStorageSizeInGbs"] = undefined /*out*/;
            resourceInputs["definedTags"] = undefined /*out*/;
            resourceInputs["displayName"] = undefined /*out*/;
            resourceInputs["exadataInfrastructureId"] = undefined /*out*/;
            resourceInputs["exascaleDbStorageVaultId"] = undefined /*out*/;
            resourceInputs["fileSystemConfigurationDetails"] = undefined /*out*/;
            resourceInputs["freeformTags"] = undefined /*out*/;
            resourceInputs["giVersion"] = undefined /*out*/;
            resourceInputs["isLocalBackupEnabled"] = undefined /*out*/;
            resourceInputs["isSparseDiskgroupEnabled"] = undefined /*out*/;
            resourceInputs["lastPatchHistoryEntryId"] = undefined /*out*/;
            resourceInputs["licenseModel"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["memorySizeInGbs"] = undefined /*out*/;
            resourceInputs["ocpusEnabled"] = undefined /*out*/;
            resourceInputs["shape"] = undefined /*out*/;
            resourceInputs["sshPublicKeys"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["storageManagementType"] = undefined /*out*/;
            resourceInputs["systemVersion"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeZone"] = undefined /*out*/;
            resourceInputs["vmClusterNetworkId"] = undefined /*out*/;
            resourceInputs["vmClusterType"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(VmClusterAddVirtualNetwork.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering VmClusterAddVirtualNetwork resources.
 */
export interface VmClusterAddVirtualNetworkState {
    /**
     * The name of the availability domain that the VM cluster is located in.
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * Specifies the properties necessary for cloud automation updates. This includes modifying the apply update time preference, enabling or disabling early adoption, and enabling, modifying, or disabling the update freeze period.
     */
    cloudAutomationUpdateDetails?: pulumi.Input<pulumi.Input<inputs.Database.VmClusterAddVirtualNetworkCloudAutomationUpdateDetail>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The compute model of the Autonomous Database. This is required if using the `computeCount` parameter. If using `cpuCoreCount` then it is an error to specify `computeModel` to a non-null value. ECPU compute model is the recommended model and OCPU compute model is legacy.
     */
    computeModel?: pulumi.Input<string>;
    /**
     * The number of enabled CPU cores.
     */
    cpusEnabled?: pulumi.Input<number>;
    /**
     * Indicates user preferences for the various diagnostic collection options for the VM cluster/Cloud VM cluster/VMBM DBCS.
     */
    dataCollectionOptions?: pulumi.Input<pulumi.Input<inputs.Database.VmClusterAddVirtualNetworkDataCollectionOption>[]>;
    /**
     * Size of the DATA disk group in GBs.
     */
    dataStorageSizeInGb?: pulumi.Input<number>;
    /**
     * Size, in terabytes, of the DATA disk group.
     */
    dataStorageSizeInTbs?: pulumi.Input<number>;
    /**
     * The local node storage allocated in GBs.
     */
    dbNodeStorageSizeInGbs?: pulumi.Input<number>;
    /**
     * The list of Exacc DB servers for the cluster to be added.
     */
    dbServers?: pulumi.Input<pulumi.Input<inputs.Database.VmClusterAddVirtualNetworkDbServer>[]>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The user-friendly name for the Exadata Cloud@Customer VM cluster. The name does not need to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     */
    exadataInfrastructureId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata Database Storage Vault.
     */
    exascaleDbStorageVaultId?: pulumi.Input<string>;
    /**
     * Details of the file system configuration of the VM cluster.
     */
    fileSystemConfigurationDetails?: pulumi.Input<pulumi.Input<inputs.Database.VmClusterAddVirtualNetworkFileSystemConfigurationDetail>[]>;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The Oracle Grid Infrastructure software version for the VM cluster.
     */
    giVersion?: pulumi.Input<string>;
    /**
     * If true, database backup on local Exadata storage is configured for the VM cluster. If false, database backup on local Exadata storage is not available in the VM cluster.
     */
    isLocalBackupEnabled?: pulumi.Input<boolean>;
    /**
     * If true, sparse disk group is configured for the VM cluster. If false, sparse disk group is not created.
     */
    isSparseDiskgroupEnabled?: pulumi.Input<boolean>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch history. This value is updated as soon as a patch operation starts.
     */
    lastPatchHistoryEntryId?: pulumi.Input<string>;
    /**
     * The Oracle license model that applies to the VM cluster. The default is LICENSE_INCLUDED.
     */
    licenseModel?: pulumi.Input<string>;
    /**
     * Additional information about the current lifecycle state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The memory allocated in GBs.
     */
    memorySizeInGbs?: pulumi.Input<number>;
    ocpusEnabled?: pulumi.Input<number>;
    /**
     * The shape of the Exadata infrastructure. The shape determines the amount of CPU, storage, and memory resources allocated to the instance.
     */
    shape?: pulumi.Input<string>;
    /**
     * The public key portion of one or more key pairs used for SSH access to the VM cluster.
     */
    sshPublicKeys?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The current state of the VM cluster.
     */
    state?: pulumi.Input<string>;
    /**
     * Specifies whether the type of storage management for the VM cluster is ASM or Exascale.
     */
    storageManagementType?: pulumi.Input<string>;
    /**
     * Operating system version of the image.
     */
    systemVersion?: pulumi.Input<string>;
    /**
     * The date and time that the VM cluster was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time zone of the Exadata infrastructure. For details, see [Exadata Infrastructure Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
     */
    timeZone?: pulumi.Input<string>;
    /**
     * The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    vmClusterId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
     */
    vmClusterNetworkId?: pulumi.Input<string>;
    /**
     * The vmcluster type for the VM cluster/Cloud VM cluster.
     */
    vmClusterType?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a VmClusterAddVirtualNetwork resource.
 */
export interface VmClusterAddVirtualNetworkArgs {
    /**
     * The list of Exacc DB servers for the cluster to be added.
     */
    dbServers: pulumi.Input<pulumi.Input<inputs.Database.VmClusterAddVirtualNetworkDbServer>[]>;
    /**
     * The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    vmClusterId: pulumi.Input<string>;
}
