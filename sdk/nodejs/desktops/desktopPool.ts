// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Desktop Pool resource in Oracle Cloud Infrastructure Desktops service.
 *
 * Creates a desktop pool with the given configuration parameters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDesktopPool = new oci.desktops.DesktopPool("test_desktop_pool", {
 *     arePrivilegedUsers: desktopPoolArePrivilegedUsers,
 *     availabilityDomain: desktopPoolAvailabilityDomain,
 *     availabilityPolicy: {
 *         startSchedule: {
 *             cronExpression: "0 10 8 ? * 2",
 *             timezone: "America/Denver",
 *         },
 *         stopSchedule: {
 *             cronExpression: "0 20 18 ? * 6",
 *             timezone: "America/Denver",
 *         },
 *     },
 *     compartmentId: compartmentId,
 *     contactDetails: desktopPoolContactDetails,
 *     devicePolicy: {
 *         audioMode: desktopPoolDevicePolicyAudioMode,
 *         cdmMode: desktopPoolDevicePolicyCdmMode,
 *         clipboardMode: desktopPoolDevicePolicyClipboardMode,
 *         isDisplayEnabled: desktopPoolDevicePolicyIsDisplayEnabled,
 *         isKeyboardEnabled: desktopPoolDevicePolicyIsKeyboardEnabled,
 *         isPointerEnabled: desktopPoolDevicePolicyIsPointerEnabled,
 *         isPrintingEnabled: desktopPoolDevicePolicyIsPrintingEnabled,
 *     },
 *     displayName: desktopPoolDisplayName,
 *     image: {
 *         imageId: testImage.id,
 *         imageName: desktopPoolImageImageName,
 *         operatingSystem: desktopPoolImageOperatingSystem,
 *     },
 *     isStorageEnabled: desktopPoolIsStorageEnabled,
 *     maximumSize: desktopPoolMaximumSize,
 *     networkConfiguration: {
 *         subnetId: testSubnet.id,
 *         vcnId: testVcn.id,
 *     },
 *     shapeName: "VM.Standard.E4.Flex",
 *     standbySize: desktopPoolStandbySize,
 *     storageBackupPolicyId: "ocid1.volumebackuppolicy.oc1.xxxxyyyyyzzzz",
 *     storageSizeInGbs: desktopPoolStorageSizeInGbs,
 *     areVolumesPreserved: desktopPoolAreVolumesPreserved,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     description: desktopPoolDescription,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     nsgIds: desktopPoolNsgIds,
 *     shapeConfig: {
 *         baselineOcpuUtilization: desktopPoolShapeConfigBaselineOcpuUtilization,
 *         memoryInGbs: desktopPoolShapeConfigMemoryInGbs,
 *         ocpus: desktopPoolShapeConfigOcpus,
 *     },
 *     privateAccessDetails: {
 *         subnetId: testSubnet.id,
 *         nsgIds: desktopPoolPrivateAccessDetailsNsgIds,
 *         privateIp: desktopPoolPrivateAccessDetailsPrivateIp,
 *     },
 *     sessionLifecycleActions: {
 *         disconnect: {
 *             action: "STOP",
 *             gracePeriodInMinutes: desktopPoolSessionLifecycleActionsDisconnectGracePeriodInMinutes,
 *         },
 *         inactivity: {
 *             action: "DISCONNECT",
 *             gracePeriodInMinutes: desktopPoolSessionLifecycleActionsInactivityGracePeriodInMinutes,
 *         },
 *     },
 *     timeStartScheduled: desktopPoolTimeStartScheduled,
 *     timeStopScheduled: desktopPoolTimeStopScheduled,
 *     useDedicatedVmHost: desktopPoolUseDedicatedVmHost,
 * });
 * ```
 *
 * ## Import
 *
 * DesktopPools can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Desktops/desktopPool:DesktopPool test_desktop_pool "id"
 * ```
 */
export class DesktopPool extends pulumi.CustomResource {
    /**
     * Get an existing DesktopPool resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DesktopPoolState, opts?: pulumi.CustomResourceOptions): DesktopPool {
        return new DesktopPool(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Desktops/desktopPool:DesktopPool';

    /**
     * Returns true if the given object is an instance of DesktopPool.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DesktopPool {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DesktopPool.__pulumiType;
    }

    /**
     * The number of active desktops in the desktop pool.
     */
    public /*out*/ readonly activeDesktops!: pulumi.Output<number>;
    /**
     * Indicates whether desktop pool users have administrative privileges on their desktop.
     */
    public readonly arePrivilegedUsers!: pulumi.Output<boolean>;
    /**
     * (Updatable) Indicates whether the volumes are preserved when a desktop pool is deleted. Default value is false.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly areVolumesPreserved!: pulumi.Output<boolean | undefined>;
    /**
     * The availability domain of the desktop pool.
     */
    public readonly availabilityDomain!: pulumi.Output<string>;
    /**
     * (Updatable) Provides the start and stop schedule information for desktop availability of the desktop pool. Use `availabilityPolicy { }` to not set a schedule.
     */
    public readonly availabilityPolicy!: pulumi.Output<outputs.Desktops.DesktopPoolAvailabilityPolicy>;
    /**
     * (Updatable) The OCID of the compartment which will contain the desktop pool.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Contact information of the desktop pool administrator. Avoid entering confidential information.
     */
    public readonly contactDetails!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A user friendly description providing additional information about the resource. Avoid entering confidential information.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) Provides the settings for desktop and client device options, such as audio in and out, client drive mapping, and clipboard access.
     */
    public readonly devicePolicy!: pulumi.Output<outputs.Desktops.DesktopPoolDevicePolicy>;
    /**
     * (Updatable) A user friendly display name. Avoid entering confidential information.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * Provides information about the desktop image.
     */
    public readonly image!: pulumi.Output<outputs.Desktops.DesktopPoolImage>;
    /**
     * Indicates whether storage is enabled for the desktop pool.
     */
    public readonly isStorageEnabled!: pulumi.Output<boolean>;
    /**
     * (Updatable) The maximum number of desktops permitted in the desktop pool.
     */
    public readonly maximumSize!: pulumi.Output<number>;
    /**
     * Provides information about the network configuration of the desktop pool.
     */
    public readonly networkConfiguration!: pulumi.Output<outputs.Desktops.DesktopPoolNetworkConfiguration>;
    /**
     * A list of network security groups for the private access.
     */
    public readonly nsgIds!: pulumi.Output<string[] | undefined>;
    /**
     * The details of the desktop's private access network connectivity to be set up for the desktop pool.
     */
    public readonly privateAccessDetails!: pulumi.Output<outputs.Desktops.DesktopPoolPrivateAccessDetails>;
    /**
     * The details of action to be triggered in case of inactivity or disconnect
     */
    public readonly sessionLifecycleActions!: pulumi.Output<outputs.Desktops.DesktopPoolSessionLifecycleActions | undefined>;
    /**
     * The compute instance shape configuration requested for each desktop in the desktop pool.
     */
    public readonly shapeConfig!: pulumi.Output<outputs.Desktops.DesktopPoolShapeConfig>;
    /**
     * The shape of the desktop pool.
     */
    public readonly shapeName!: pulumi.Output<string>;
    /**
     * (Updatable) The maximum number of standby desktops available in the desktop pool.
     */
    public readonly standbySize!: pulumi.Output<number>;
    /**
     * The current state of the desktop pool.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The backup policy OCID of the storage.
     */
    public readonly storageBackupPolicyId!: pulumi.Output<string>;
    /**
     * The size in GBs of the storage for the desktop pool.
     */
    public readonly storageSizeInGbs!: pulumi.Output<number>;
    /**
     * The date and time the resource was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * (Updatable) The start time of the desktop pool.
     */
    public readonly timeStartScheduled!: pulumi.Output<string | undefined>;
    /**
     * (Updatable) The stop time of the desktop pool.
     */
    public readonly timeStopScheduled!: pulumi.Output<string | undefined>;
    /**
     * Indicates whether the desktop pool uses dedicated virtual machine hosts.
     */
    public readonly useDedicatedVmHost!: pulumi.Output<string>;

    /**
     * Create a DesktopPool resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DesktopPoolArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DesktopPoolArgs | DesktopPoolState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as DesktopPoolState | undefined;
            resourceInputs["activeDesktops"] = state ? state.activeDesktops : undefined;
            resourceInputs["arePrivilegedUsers"] = state ? state.arePrivilegedUsers : undefined;
            resourceInputs["areVolumesPreserved"] = state ? state.areVolumesPreserved : undefined;
            resourceInputs["availabilityDomain"] = state ? state.availabilityDomain : undefined;
            resourceInputs["availabilityPolicy"] = state ? state.availabilityPolicy : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["contactDetails"] = state ? state.contactDetails : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["devicePolicy"] = state ? state.devicePolicy : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["image"] = state ? state.image : undefined;
            resourceInputs["isStorageEnabled"] = state ? state.isStorageEnabled : undefined;
            resourceInputs["maximumSize"] = state ? state.maximumSize : undefined;
            resourceInputs["networkConfiguration"] = state ? state.networkConfiguration : undefined;
            resourceInputs["nsgIds"] = state ? state.nsgIds : undefined;
            resourceInputs["privateAccessDetails"] = state ? state.privateAccessDetails : undefined;
            resourceInputs["sessionLifecycleActions"] = state ? state.sessionLifecycleActions : undefined;
            resourceInputs["shapeConfig"] = state ? state.shapeConfig : undefined;
            resourceInputs["shapeName"] = state ? state.shapeName : undefined;
            resourceInputs["standbySize"] = state ? state.standbySize : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["storageBackupPolicyId"] = state ? state.storageBackupPolicyId : undefined;
            resourceInputs["storageSizeInGbs"] = state ? state.storageSizeInGbs : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeStartScheduled"] = state ? state.timeStartScheduled : undefined;
            resourceInputs["timeStopScheduled"] = state ? state.timeStopScheduled : undefined;
            resourceInputs["useDedicatedVmHost"] = state ? state.useDedicatedVmHost : undefined;
        } else {
            const args = argsOrState as DesktopPoolArgs | undefined;
            if ((!args || args.arePrivilegedUsers === undefined) && !opts.urn) {
                throw new Error("Missing required property 'arePrivilegedUsers'");
            }
            if ((!args || args.availabilityDomain === undefined) && !opts.urn) {
                throw new Error("Missing required property 'availabilityDomain'");
            }
            if ((!args || args.availabilityPolicy === undefined) && !opts.urn) {
                throw new Error("Missing required property 'availabilityPolicy'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.contactDetails === undefined) && !opts.urn) {
                throw new Error("Missing required property 'contactDetails'");
            }
            if ((!args || args.devicePolicy === undefined) && !opts.urn) {
                throw new Error("Missing required property 'devicePolicy'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.image === undefined) && !opts.urn) {
                throw new Error("Missing required property 'image'");
            }
            if ((!args || args.isStorageEnabled === undefined) && !opts.urn) {
                throw new Error("Missing required property 'isStorageEnabled'");
            }
            if ((!args || args.maximumSize === undefined) && !opts.urn) {
                throw new Error("Missing required property 'maximumSize'");
            }
            if ((!args || args.networkConfiguration === undefined) && !opts.urn) {
                throw new Error("Missing required property 'networkConfiguration'");
            }
            if ((!args || args.shapeName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'shapeName'");
            }
            if ((!args || args.standbySize === undefined) && !opts.urn) {
                throw new Error("Missing required property 'standbySize'");
            }
            if ((!args || args.storageBackupPolicyId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'storageBackupPolicyId'");
            }
            if ((!args || args.storageSizeInGbs === undefined) && !opts.urn) {
                throw new Error("Missing required property 'storageSizeInGbs'");
            }
            resourceInputs["arePrivilegedUsers"] = args ? args.arePrivilegedUsers : undefined;
            resourceInputs["areVolumesPreserved"] = args ? args.areVolumesPreserved : undefined;
            resourceInputs["availabilityDomain"] = args ? args.availabilityDomain : undefined;
            resourceInputs["availabilityPolicy"] = args ? args.availabilityPolicy : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["contactDetails"] = args ? args.contactDetails : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["devicePolicy"] = args ? args.devicePolicy : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["image"] = args ? args.image : undefined;
            resourceInputs["isStorageEnabled"] = args ? args.isStorageEnabled : undefined;
            resourceInputs["maximumSize"] = args ? args.maximumSize : undefined;
            resourceInputs["networkConfiguration"] = args ? args.networkConfiguration : undefined;
            resourceInputs["nsgIds"] = args ? args.nsgIds : undefined;
            resourceInputs["privateAccessDetails"] = args ? args.privateAccessDetails : undefined;
            resourceInputs["sessionLifecycleActions"] = args ? args.sessionLifecycleActions : undefined;
            resourceInputs["shapeConfig"] = args ? args.shapeConfig : undefined;
            resourceInputs["shapeName"] = args ? args.shapeName : undefined;
            resourceInputs["standbySize"] = args ? args.standbySize : undefined;
            resourceInputs["storageBackupPolicyId"] = args ? args.storageBackupPolicyId : undefined;
            resourceInputs["storageSizeInGbs"] = args ? args.storageSizeInGbs : undefined;
            resourceInputs["timeStartScheduled"] = args ? args.timeStartScheduled : undefined;
            resourceInputs["timeStopScheduled"] = args ? args.timeStopScheduled : undefined;
            resourceInputs["useDedicatedVmHost"] = args ? args.useDedicatedVmHost : undefined;
            resourceInputs["activeDesktops"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(DesktopPool.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DesktopPool resources.
 */
export interface DesktopPoolState {
    /**
     * The number of active desktops in the desktop pool.
     */
    activeDesktops?: pulumi.Input<number>;
    /**
     * Indicates whether desktop pool users have administrative privileges on their desktop.
     */
    arePrivilegedUsers?: pulumi.Input<boolean>;
    /**
     * (Updatable) Indicates whether the volumes are preserved when a desktop pool is deleted. Default value is false.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    areVolumesPreserved?: pulumi.Input<boolean>;
    /**
     * The availability domain of the desktop pool.
     */
    availabilityDomain?: pulumi.Input<string>;
    /**
     * (Updatable) Provides the start and stop schedule information for desktop availability of the desktop pool. Use `availabilityPolicy { }` to not set a schedule.
     */
    availabilityPolicy?: pulumi.Input<inputs.Desktops.DesktopPoolAvailabilityPolicy>;
    /**
     * (Updatable) The OCID of the compartment which will contain the desktop pool.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Contact information of the desktop pool administrator. Avoid entering confidential information.
     */
    contactDetails?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user friendly description providing additional information about the resource. Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Provides the settings for desktop and client device options, such as audio in and out, client drive mapping, and clipboard access.
     */
    devicePolicy?: pulumi.Input<inputs.Desktops.DesktopPoolDevicePolicy>;
    /**
     * (Updatable) A user friendly display name. Avoid entering confidential information.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Provides information about the desktop image.
     */
    image?: pulumi.Input<inputs.Desktops.DesktopPoolImage>;
    /**
     * Indicates whether storage is enabled for the desktop pool.
     */
    isStorageEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) The maximum number of desktops permitted in the desktop pool.
     */
    maximumSize?: pulumi.Input<number>;
    /**
     * Provides information about the network configuration of the desktop pool.
     */
    networkConfiguration?: pulumi.Input<inputs.Desktops.DesktopPoolNetworkConfiguration>;
    /**
     * A list of network security groups for the private access.
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The details of the desktop's private access network connectivity to be set up for the desktop pool.
     */
    privateAccessDetails?: pulumi.Input<inputs.Desktops.DesktopPoolPrivateAccessDetails>;
    /**
     * The details of action to be triggered in case of inactivity or disconnect
     */
    sessionLifecycleActions?: pulumi.Input<inputs.Desktops.DesktopPoolSessionLifecycleActions>;
    /**
     * The compute instance shape configuration requested for each desktop in the desktop pool.
     */
    shapeConfig?: pulumi.Input<inputs.Desktops.DesktopPoolShapeConfig>;
    /**
     * The shape of the desktop pool.
     */
    shapeName?: pulumi.Input<string>;
    /**
     * (Updatable) The maximum number of standby desktops available in the desktop pool.
     */
    standbySize?: pulumi.Input<number>;
    /**
     * The current state of the desktop pool.
     */
    state?: pulumi.Input<string>;
    /**
     * The backup policy OCID of the storage.
     */
    storageBackupPolicyId?: pulumi.Input<string>;
    /**
     * The size in GBs of the storage for the desktop pool.
     */
    storageSizeInGbs?: pulumi.Input<number>;
    /**
     * The date and time the resource was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * (Updatable) The start time of the desktop pool.
     */
    timeStartScheduled?: pulumi.Input<string>;
    /**
     * (Updatable) The stop time of the desktop pool.
     */
    timeStopScheduled?: pulumi.Input<string>;
    /**
     * Indicates whether the desktop pool uses dedicated virtual machine hosts.
     */
    useDedicatedVmHost?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a DesktopPool resource.
 */
export interface DesktopPoolArgs {
    /**
     * Indicates whether desktop pool users have administrative privileges on their desktop.
     */
    arePrivilegedUsers: pulumi.Input<boolean>;
    /**
     * (Updatable) Indicates whether the volumes are preserved when a desktop pool is deleted. Default value is false.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    areVolumesPreserved?: pulumi.Input<boolean>;
    /**
     * The availability domain of the desktop pool.
     */
    availabilityDomain: pulumi.Input<string>;
    /**
     * (Updatable) Provides the start and stop schedule information for desktop availability of the desktop pool. Use `availabilityPolicy { }` to not set a schedule.
     */
    availabilityPolicy: pulumi.Input<inputs.Desktops.DesktopPoolAvailabilityPolicy>;
    /**
     * (Updatable) The OCID of the compartment which will contain the desktop pool.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Contact information of the desktop pool administrator. Avoid entering confidential information.
     */
    contactDetails: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user friendly description providing additional information about the resource. Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Provides the settings for desktop and client device options, such as audio in and out, client drive mapping, and clipboard access.
     */
    devicePolicy: pulumi.Input<inputs.Desktops.DesktopPoolDevicePolicy>;
    /**
     * (Updatable) A user friendly display name. Avoid entering confidential information.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * Provides information about the desktop image.
     */
    image: pulumi.Input<inputs.Desktops.DesktopPoolImage>;
    /**
     * Indicates whether storage is enabled for the desktop pool.
     */
    isStorageEnabled: pulumi.Input<boolean>;
    /**
     * (Updatable) The maximum number of desktops permitted in the desktop pool.
     */
    maximumSize: pulumi.Input<number>;
    /**
     * Provides information about the network configuration of the desktop pool.
     */
    networkConfiguration: pulumi.Input<inputs.Desktops.DesktopPoolNetworkConfiguration>;
    /**
     * A list of network security groups for the private access.
     */
    nsgIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The details of the desktop's private access network connectivity to be set up for the desktop pool.
     */
    privateAccessDetails?: pulumi.Input<inputs.Desktops.DesktopPoolPrivateAccessDetails>;
    /**
     * The details of action to be triggered in case of inactivity or disconnect
     */
    sessionLifecycleActions?: pulumi.Input<inputs.Desktops.DesktopPoolSessionLifecycleActions>;
    /**
     * The compute instance shape configuration requested for each desktop in the desktop pool.
     */
    shapeConfig?: pulumi.Input<inputs.Desktops.DesktopPoolShapeConfig>;
    /**
     * The shape of the desktop pool.
     */
    shapeName: pulumi.Input<string>;
    /**
     * (Updatable) The maximum number of standby desktops available in the desktop pool.
     */
    standbySize: pulumi.Input<number>;
    /**
     * The backup policy OCID of the storage.
     */
    storageBackupPolicyId: pulumi.Input<string>;
    /**
     * The size in GBs of the storage for the desktop pool.
     */
    storageSizeInGbs: pulumi.Input<number>;
    /**
     * (Updatable) The start time of the desktop pool.
     */
    timeStartScheduled?: pulumi.Input<string>;
    /**
     * (Updatable) The stop time of the desktop pool.
     */
    timeStopScheduled?: pulumi.Input<string>;
    /**
     * Indicates whether the desktop pool uses dedicated virtual machine hosts.
     */
    useDedicatedVmHost?: pulumi.Input<string>;
}
