// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Managed Instance resource in Oracle Cloud Infrastructure OS Management service.
 *
 * Updates a specific Managed Instance.
 *
 * ## Import
 *
 * ManagedInstances can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:OsManagement/managedInstance:ManagedInstance test_managed_instance "id"
 * ```
 */
export class ManagedInstance extends pulumi.CustomResource {
    /**
     * Get an existing ManagedInstance resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ManagedInstanceState, opts?: pulumi.CustomResourceOptions): ManagedInstance {
        return new ManagedInstance(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:OsManagement/managedInstance:ManagedInstance';

    /**
     * Returns true if the given object is an instance of ManagedInstance.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ManagedInstance {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ManagedInstance.__pulumiType;
    }

    /**
     * if present, indicates the Managed Instance is an autonomous instance. Holds all the Autonomous specific information
     */
    public /*out*/ readonly autonomouses!: pulumi.Output<outputs.OsManagement.ManagedInstanceAutonomouse[]>;
    /**
     * Number of bug fix type updates available to be installed
     */
    public /*out*/ readonly bugUpdatesAvailable!: pulumi.Output<number>;
    /**
     * list of child Software Sources attached to the Managed Instance
     */
    public /*out*/ readonly childSoftwareSources!: pulumi.Output<outputs.OsManagement.ManagedInstanceChildSoftwareSource[]>;
    /**
     * OCID for the Compartment
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * Information specified by the user about the managed instance
     */
    public /*out*/ readonly description!: pulumi.Output<string>;
    /**
     * User friendly name
     */
    public /*out*/ readonly displayName!: pulumi.Output<string>;
    /**
     * Number of enhancement type updates available to be installed
     */
    public /*out*/ readonly enhancementUpdatesAvailable!: pulumi.Output<number>;
    /**
     * (Updatable) True if user allow data collection for this instance
     */
    public readonly isDataCollectionAuthorized!: pulumi.Output<boolean>;
    /**
     * Indicates whether a reboot is required to complete installation of updates.
     */
    public /*out*/ readonly isRebootRequired!: pulumi.Output<boolean>;
    /**
     * The ksplice effective kernel version
     */
    public /*out*/ readonly kspliceEffectiveKernelVersion!: pulumi.Output<string>;
    /**
     * Time at which the instance last booted
     */
    public /*out*/ readonly lastBoot!: pulumi.Output<string>;
    /**
     * Time at which the instance last checked in
     */
    public /*out*/ readonly lastCheckin!: pulumi.Output<string>;
    /**
     * The ids of the managed instance groups of which this instance is a member.
     */
    public /*out*/ readonly managedInstanceGroups!: pulumi.Output<outputs.OsManagement.ManagedInstanceManagedInstanceGroup[]>;
    /**
     * OCID for the managed instance
     */
    public readonly managedInstanceId!: pulumi.Output<string>;
    /**
     * (Updatable) OCID of the ONS topic used to send notification to users
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly notificationTopicId!: pulumi.Output<string>;
    /**
     * The Operating System type of the managed instance.
     */
    public /*out*/ readonly osFamily!: pulumi.Output<string>;
    /**
     * Operating System Kernel Version
     */
    public /*out*/ readonly osKernelVersion!: pulumi.Output<string>;
    /**
     * Operating System Name
     */
    public /*out*/ readonly osName!: pulumi.Output<string>;
    /**
     * Operating System Version
     */
    public /*out*/ readonly osVersion!: pulumi.Output<string>;
    /**
     * Number of non-classified updates available to be installed
     */
    public /*out*/ readonly otherUpdatesAvailable!: pulumi.Output<number>;
    /**
     * the parent (base) Software Source attached to the Managed Instance
     */
    public /*out*/ readonly parentSoftwareSources!: pulumi.Output<outputs.OsManagement.ManagedInstanceParentSoftwareSource[]>;
    /**
     * Number of scheduled jobs associated with this instance
     */
    public /*out*/ readonly scheduledJobCount!: pulumi.Output<number>;
    /**
     * Number of security type updates available to be installed
     */
    public /*out*/ readonly securityUpdatesAvailable!: pulumi.Output<number>;
    /**
     * status of the managed instance.
     */
    public /*out*/ readonly status!: pulumi.Output<string>;
    /**
     * Number of updates available to be installed
     */
    public /*out*/ readonly updatesAvailable!: pulumi.Output<number>;
    /**
     * Number of work requests associated with this instance
     */
    public /*out*/ readonly workRequestCount!: pulumi.Output<number>;

    /**
     * Create a ManagedInstance resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ManagedInstanceArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ManagedInstanceArgs | ManagedInstanceState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ManagedInstanceState | undefined;
            resourceInputs["autonomouses"] = state ? state.autonomouses : undefined;
            resourceInputs["bugUpdatesAvailable"] = state ? state.bugUpdatesAvailable : undefined;
            resourceInputs["childSoftwareSources"] = state ? state.childSoftwareSources : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["enhancementUpdatesAvailable"] = state ? state.enhancementUpdatesAvailable : undefined;
            resourceInputs["isDataCollectionAuthorized"] = state ? state.isDataCollectionAuthorized : undefined;
            resourceInputs["isRebootRequired"] = state ? state.isRebootRequired : undefined;
            resourceInputs["kspliceEffectiveKernelVersion"] = state ? state.kspliceEffectiveKernelVersion : undefined;
            resourceInputs["lastBoot"] = state ? state.lastBoot : undefined;
            resourceInputs["lastCheckin"] = state ? state.lastCheckin : undefined;
            resourceInputs["managedInstanceGroups"] = state ? state.managedInstanceGroups : undefined;
            resourceInputs["managedInstanceId"] = state ? state.managedInstanceId : undefined;
            resourceInputs["notificationTopicId"] = state ? state.notificationTopicId : undefined;
            resourceInputs["osFamily"] = state ? state.osFamily : undefined;
            resourceInputs["osKernelVersion"] = state ? state.osKernelVersion : undefined;
            resourceInputs["osName"] = state ? state.osName : undefined;
            resourceInputs["osVersion"] = state ? state.osVersion : undefined;
            resourceInputs["otherUpdatesAvailable"] = state ? state.otherUpdatesAvailable : undefined;
            resourceInputs["parentSoftwareSources"] = state ? state.parentSoftwareSources : undefined;
            resourceInputs["scheduledJobCount"] = state ? state.scheduledJobCount : undefined;
            resourceInputs["securityUpdatesAvailable"] = state ? state.securityUpdatesAvailable : undefined;
            resourceInputs["status"] = state ? state.status : undefined;
            resourceInputs["updatesAvailable"] = state ? state.updatesAvailable : undefined;
            resourceInputs["workRequestCount"] = state ? state.workRequestCount : undefined;
        } else {
            const args = argsOrState as ManagedInstanceArgs | undefined;
            if ((!args || args.managedInstanceId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'managedInstanceId'");
            }
            resourceInputs["isDataCollectionAuthorized"] = args ? args.isDataCollectionAuthorized : undefined;
            resourceInputs["managedInstanceId"] = args ? args.managedInstanceId : undefined;
            resourceInputs["notificationTopicId"] = args ? args.notificationTopicId : undefined;
            resourceInputs["autonomouses"] = undefined /*out*/;
            resourceInputs["bugUpdatesAvailable"] = undefined /*out*/;
            resourceInputs["childSoftwareSources"] = undefined /*out*/;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["description"] = undefined /*out*/;
            resourceInputs["displayName"] = undefined /*out*/;
            resourceInputs["enhancementUpdatesAvailable"] = undefined /*out*/;
            resourceInputs["isRebootRequired"] = undefined /*out*/;
            resourceInputs["kspliceEffectiveKernelVersion"] = undefined /*out*/;
            resourceInputs["lastBoot"] = undefined /*out*/;
            resourceInputs["lastCheckin"] = undefined /*out*/;
            resourceInputs["managedInstanceGroups"] = undefined /*out*/;
            resourceInputs["osFamily"] = undefined /*out*/;
            resourceInputs["osKernelVersion"] = undefined /*out*/;
            resourceInputs["osName"] = undefined /*out*/;
            resourceInputs["osVersion"] = undefined /*out*/;
            resourceInputs["otherUpdatesAvailable"] = undefined /*out*/;
            resourceInputs["parentSoftwareSources"] = undefined /*out*/;
            resourceInputs["scheduledJobCount"] = undefined /*out*/;
            resourceInputs["securityUpdatesAvailable"] = undefined /*out*/;
            resourceInputs["status"] = undefined /*out*/;
            resourceInputs["updatesAvailable"] = undefined /*out*/;
            resourceInputs["workRequestCount"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ManagedInstance.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ManagedInstance resources.
 */
export interface ManagedInstanceState {
    /**
     * if present, indicates the Managed Instance is an autonomous instance. Holds all the Autonomous specific information
     */
    autonomouses?: pulumi.Input<pulumi.Input<inputs.OsManagement.ManagedInstanceAutonomouse>[]>;
    /**
     * Number of bug fix type updates available to be installed
     */
    bugUpdatesAvailable?: pulumi.Input<number>;
    /**
     * list of child Software Sources attached to the Managed Instance
     */
    childSoftwareSources?: pulumi.Input<pulumi.Input<inputs.OsManagement.ManagedInstanceChildSoftwareSource>[]>;
    /**
     * OCID for the Compartment
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Information specified by the user about the managed instance
     */
    description?: pulumi.Input<string>;
    /**
     * User friendly name
     */
    displayName?: pulumi.Input<string>;
    /**
     * Number of enhancement type updates available to be installed
     */
    enhancementUpdatesAvailable?: pulumi.Input<number>;
    /**
     * (Updatable) True if user allow data collection for this instance
     */
    isDataCollectionAuthorized?: pulumi.Input<boolean>;
    /**
     * Indicates whether a reboot is required to complete installation of updates.
     */
    isRebootRequired?: pulumi.Input<boolean>;
    /**
     * The ksplice effective kernel version
     */
    kspliceEffectiveKernelVersion?: pulumi.Input<string>;
    /**
     * Time at which the instance last booted
     */
    lastBoot?: pulumi.Input<string>;
    /**
     * Time at which the instance last checked in
     */
    lastCheckin?: pulumi.Input<string>;
    /**
     * The ids of the managed instance groups of which this instance is a member.
     */
    managedInstanceGroups?: pulumi.Input<pulumi.Input<inputs.OsManagement.ManagedInstanceManagedInstanceGroup>[]>;
    /**
     * OCID for the managed instance
     */
    managedInstanceId?: pulumi.Input<string>;
    /**
     * (Updatable) OCID of the ONS topic used to send notification to users
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    notificationTopicId?: pulumi.Input<string>;
    /**
     * The Operating System type of the managed instance.
     */
    osFamily?: pulumi.Input<string>;
    /**
     * Operating System Kernel Version
     */
    osKernelVersion?: pulumi.Input<string>;
    /**
     * Operating System Name
     */
    osName?: pulumi.Input<string>;
    /**
     * Operating System Version
     */
    osVersion?: pulumi.Input<string>;
    /**
     * Number of non-classified updates available to be installed
     */
    otherUpdatesAvailable?: pulumi.Input<number>;
    /**
     * the parent (base) Software Source attached to the Managed Instance
     */
    parentSoftwareSources?: pulumi.Input<pulumi.Input<inputs.OsManagement.ManagedInstanceParentSoftwareSource>[]>;
    /**
     * Number of scheduled jobs associated with this instance
     */
    scheduledJobCount?: pulumi.Input<number>;
    /**
     * Number of security type updates available to be installed
     */
    securityUpdatesAvailable?: pulumi.Input<number>;
    /**
     * status of the managed instance.
     */
    status?: pulumi.Input<string>;
    /**
     * Number of updates available to be installed
     */
    updatesAvailable?: pulumi.Input<number>;
    /**
     * Number of work requests associated with this instance
     */
    workRequestCount?: pulumi.Input<number>;
}

/**
 * The set of arguments for constructing a ManagedInstance resource.
 */
export interface ManagedInstanceArgs {
    /**
     * (Updatable) True if user allow data collection for this instance
     */
    isDataCollectionAuthorized?: pulumi.Input<boolean>;
    /**
     * OCID for the managed instance
     */
    managedInstanceId: pulumi.Input<string>;
    /**
     * (Updatable) OCID of the ONS topic used to send notification to users
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    notificationTopicId?: pulumi.Input<string>;
}
