// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Vm Cluster Remove Virtual Machine resource in Oracle Cloud Infrastructure Database service.
 *
 * Remove Virtual Machines from the VM cluster. Applies to Exadata Cloud@Customer instances only.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVmClusterRemoveVirtualMachine = new oci.database.VmClusterRemoveVirtualMachine("testVmClusterRemoveVirtualMachine", {
 *     dbServers: [{
 *         dbServerId: oci_database_db_server.test_db_server.id,
 *     }],
 *     vmClusterId: oci_database_vm_cluster.test_vm_cluster.id,
 * });
 * ```
 *
 * ## Import
 *
 * VmClusterRemoveVirtualMachine can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:Database/vmClusterRemoveVirtualMachine:VmClusterRemoveVirtualMachine test_vm_cluster_remove_virtual_machine "id"
 * ```
 */
export class VmClusterRemoveVirtualMachine extends pulumi.CustomResource {
    /**
     * Get an existing VmClusterRemoveVirtualMachine resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: VmClusterRemoveVirtualMachineState, opts?: pulumi.CustomResourceOptions): VmClusterRemoveVirtualMachine {
        return new VmClusterRemoveVirtualMachine(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Database/vmClusterRemoveVirtualMachine:VmClusterRemoveVirtualMachine';

    /**
     * Returns true if the given object is an instance of VmClusterRemoveVirtualMachine.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is VmClusterRemoveVirtualMachine {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === VmClusterRemoveVirtualMachine.__pulumiType;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * The number of enabled CPU cores.
     */
    public /*out*/ readonly cpusEnabled!: pulumi.Output<number>;
    /**
     * Indicates user preferences for the various diagnostic collection options for the VM cluster/Cloud VM cluster/VMBM DBCS.
     */
    public /*out*/ readonly dataCollectionOptions!: pulumi.Output<outputs.Database.VmClusterRemoveVirtualMachineDataCollectionOption[]>;
    /**
     * Size, in terabytes, of the DATA disk group.
     */
    public /*out*/ readonly dataStorageSizeInTbs!: pulumi.Output<number>;
    /**
     * The local node storage allocated in GBs.
     */
    public /*out*/ readonly dbNodeStorageSizeInGbs!: pulumi.Output<number>;
    /**
     * The list of Exacc DB servers for the cluster to be removed.
     */
    public readonly dbServers!: pulumi.Output<outputs.Database.VmClusterRemoveVirtualMachineDbServer[]>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    public /*out*/ readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The user-friendly name for the Exadata Cloud@Customer VM cluster. The name does not need to be unique.
     */
    public /*out*/ readonly displayName!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     */
    public /*out*/ readonly exadataInfrastructureId!: pulumi.Output<string>;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public /*out*/ readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
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
     */
    public readonly vmClusterId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
     */
    public /*out*/ readonly vmClusterNetworkId!: pulumi.Output<string>;

    /**
     * Create a VmClusterRemoveVirtualMachine resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: VmClusterRemoveVirtualMachineArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: VmClusterRemoveVirtualMachineArgs | VmClusterRemoveVirtualMachineState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as VmClusterRemoveVirtualMachineState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["cpusEnabled"] = state ? state.cpusEnabled : undefined;
            resourceInputs["dataCollectionOptions"] = state ? state.dataCollectionOptions : undefined;
            resourceInputs["dataStorageSizeInTbs"] = state ? state.dataStorageSizeInTbs : undefined;
            resourceInputs["dbNodeStorageSizeInGbs"] = state ? state.dbNodeStorageSizeInGbs : undefined;
            resourceInputs["dbServers"] = state ? state.dbServers : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["exadataInfrastructureId"] = state ? state.exadataInfrastructureId : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["giVersion"] = state ? state.giVersion : undefined;
            resourceInputs["isLocalBackupEnabled"] = state ? state.isLocalBackupEnabled : undefined;
            resourceInputs["isSparseDiskgroupEnabled"] = state ? state.isSparseDiskgroupEnabled : undefined;
            resourceInputs["lastPatchHistoryEntryId"] = state ? state.lastPatchHistoryEntryId : undefined;
            resourceInputs["licenseModel"] = state ? state.licenseModel : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["memorySizeInGbs"] = state ? state.memorySizeInGbs : undefined;
            resourceInputs["shape"] = state ? state.shape : undefined;
            resourceInputs["sshPublicKeys"] = state ? state.sshPublicKeys : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemVersion"] = state ? state.systemVersion : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeZone"] = state ? state.timeZone : undefined;
            resourceInputs["vmClusterId"] = state ? state.vmClusterId : undefined;
            resourceInputs["vmClusterNetworkId"] = state ? state.vmClusterNetworkId : undefined;
        } else {
            const args = argsOrState as VmClusterRemoveVirtualMachineArgs | undefined;
            if ((!args || args.dbServers === undefined) && !opts.urn) {
                throw new Error("Missing required property 'dbServers'");
            }
            if ((!args || args.vmClusterId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'vmClusterId'");
            }
            resourceInputs["dbServers"] = args ? args.dbServers : undefined;
            resourceInputs["vmClusterId"] = args ? args.vmClusterId : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["cpusEnabled"] = undefined /*out*/;
            resourceInputs["dataCollectionOptions"] = undefined /*out*/;
            resourceInputs["dataStorageSizeInTbs"] = undefined /*out*/;
            resourceInputs["dbNodeStorageSizeInGbs"] = undefined /*out*/;
            resourceInputs["definedTags"] = undefined /*out*/;
            resourceInputs["displayName"] = undefined /*out*/;
            resourceInputs["exadataInfrastructureId"] = undefined /*out*/;
            resourceInputs["freeformTags"] = undefined /*out*/;
            resourceInputs["giVersion"] = undefined /*out*/;
            resourceInputs["isLocalBackupEnabled"] = undefined /*out*/;
            resourceInputs["isSparseDiskgroupEnabled"] = undefined /*out*/;
            resourceInputs["lastPatchHistoryEntryId"] = undefined /*out*/;
            resourceInputs["licenseModel"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["memorySizeInGbs"] = undefined /*out*/;
            resourceInputs["shape"] = undefined /*out*/;
            resourceInputs["sshPublicKeys"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemVersion"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeZone"] = undefined /*out*/;
            resourceInputs["vmClusterNetworkId"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(VmClusterRemoveVirtualMachine.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering VmClusterRemoveVirtualMachine resources.
 */
export interface VmClusterRemoveVirtualMachineState {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The number of enabled CPU cores.
     */
    cpusEnabled?: pulumi.Input<number>;
    /**
     * Indicates user preferences for the various diagnostic collection options for the VM cluster/Cloud VM cluster/VMBM DBCS.
     */
    dataCollectionOptions?: pulumi.Input<pulumi.Input<inputs.Database.VmClusterRemoveVirtualMachineDataCollectionOption>[]>;
    /**
     * Size, in terabytes, of the DATA disk group.
     */
    dataStorageSizeInTbs?: pulumi.Input<number>;
    /**
     * The local node storage allocated in GBs.
     */
    dbNodeStorageSizeInGbs?: pulumi.Input<number>;
    /**
     * The list of Exacc DB servers for the cluster to be removed.
     */
    dbServers?: pulumi.Input<pulumi.Input<inputs.Database.VmClusterRemoveVirtualMachineDbServer>[]>;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The user-friendly name for the Exadata Cloud@Customer VM cluster. The name does not need to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     */
    exadataInfrastructureId?: pulumi.Input<string>;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
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
     */
    vmClusterId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
     */
    vmClusterNetworkId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a VmClusterRemoveVirtualMachine resource.
 */
export interface VmClusterRemoveVirtualMachineArgs {
    /**
     * The list of Exacc DB servers for the cluster to be removed.
     */
    dbServers: pulumi.Input<pulumi.Input<inputs.Database.VmClusterRemoveVirtualMachineDbServer>[]>;
    /**
     * The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    vmClusterId: pulumi.Input<string>;
}