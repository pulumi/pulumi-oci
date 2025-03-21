// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Managed Instance Management in Oracle Cloud Infrastructure OS Management service.
 * The resource can be used to attach/detach parent software source, child software sources and managed instance groups from managed instances.
 *
 * Adds a parent software source to a managed instance. After the software source has been added, then packages from that software source can be installed on the managed instance. Software sources that have this software source as a parent will be able to be added to this managed instance.
 * Removes a software source from a managed instance. All child software sources will also be removed from the managed instance. Packages will no longer be able to be installed from these software sources.
 *
 * Adds a child software source to a managed instance. After the software source has been added, then packages from that software source can be installed on the managed instance.\
 * Removes a child software source from a managed instance. Packages will no longer be able to be installed from these software sources.
 *
 * Adds a Managed Instance to a Managed Instance Group. After the Managed Instance has been added, then operations can be performed on the Managed Instance Group which will then apply to all Managed Instances in the group.
 * Removes a Managed Instance from a Managed Instance Group.
 *
 * **NOTE** The resource on CREATE will detach any already attached parent software source, child software sources, managed instance groups to the managed instance.
 * Destroying this resource will not delete any associations.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedInstanceManagement = new oci.osmanagement.ManagedInstanceManagement("test_managed_instance_management", {
 *     managedInstanceId: testManagedInstance.id,
 *     parentSoftwareSource: {
 *         id: testParentSoftwareSource.id,
 *         name: testParentSoftwareSource.displayName,
 *     },
 *     managedInstanceGroups: [{
 *         id: testManagedInstanceGroup.id,
 *         displayName: managedInstanceGroupDisplayName,
 *     }],
 *     childSoftwareSources: [{
 *         id: testSoftwareSourceChild.id,
 *         name: testSoftwareSourceChild.displayName,
 *     }],
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class ManagedInstanceManagement extends pulumi.CustomResource {
    /**
     * Get an existing ManagedInstanceManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ManagedInstanceManagementState, opts?: pulumi.CustomResourceOptions): ManagedInstanceManagement {
        return new ManagedInstanceManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:OsManagement/managedInstanceManagement:ManagedInstanceManagement';

    /**
     * Returns true if the given object is an instance of ManagedInstanceManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ManagedInstanceManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ManagedInstanceManagement.__pulumiType;
    }

    /**
     * (Updatable) list of child Software Sources attached to the Managed Instance
     */
    public readonly childSoftwareSources!: pulumi.Output<outputs.OsManagement.ManagedInstanceManagementChildSoftwareSource[]>;
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
     * Time at which the instance last booted
     */
    public /*out*/ readonly lastBoot!: pulumi.Output<string>;
    /**
     * Time at which the instance last checked in
     */
    public /*out*/ readonly lastCheckin!: pulumi.Output<string>;
    /**
     * (Updatable) The ids of the managed instance groups of which this instance is a member.
     */
    public readonly managedInstanceGroups!: pulumi.Output<outputs.OsManagement.ManagedInstanceManagementManagedInstanceGroup[]>;
    /**
     * OCID for the managed instance
     */
    public readonly managedInstanceId!: pulumi.Output<string>;
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
     * (Updatable) the parent (base) Software Source attached to the Managed Instance
     */
    public readonly parentSoftwareSource!: pulumi.Output<outputs.OsManagement.ManagedInstanceManagementParentSoftwareSource>;
    /**
     * status of the managed instance.
     */
    public /*out*/ readonly status!: pulumi.Output<string>;
    /**
     * Number of updates available to be installed
     */
    public /*out*/ readonly updatesAvailable!: pulumi.Output<number>;

    /**
     * Create a ManagedInstanceManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ManagedInstanceManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ManagedInstanceManagementArgs | ManagedInstanceManagementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ManagedInstanceManagementState | undefined;
            resourceInputs["childSoftwareSources"] = state ? state.childSoftwareSources : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["lastBoot"] = state ? state.lastBoot : undefined;
            resourceInputs["lastCheckin"] = state ? state.lastCheckin : undefined;
            resourceInputs["managedInstanceGroups"] = state ? state.managedInstanceGroups : undefined;
            resourceInputs["managedInstanceId"] = state ? state.managedInstanceId : undefined;
            resourceInputs["osKernelVersion"] = state ? state.osKernelVersion : undefined;
            resourceInputs["osName"] = state ? state.osName : undefined;
            resourceInputs["osVersion"] = state ? state.osVersion : undefined;
            resourceInputs["parentSoftwareSource"] = state ? state.parentSoftwareSource : undefined;
            resourceInputs["status"] = state ? state.status : undefined;
            resourceInputs["updatesAvailable"] = state ? state.updatesAvailable : undefined;
        } else {
            const args = argsOrState as ManagedInstanceManagementArgs | undefined;
            if ((!args || args.managedInstanceId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'managedInstanceId'");
            }
            resourceInputs["childSoftwareSources"] = args ? args.childSoftwareSources : undefined;
            resourceInputs["managedInstanceGroups"] = args ? args.managedInstanceGroups : undefined;
            resourceInputs["managedInstanceId"] = args ? args.managedInstanceId : undefined;
            resourceInputs["parentSoftwareSource"] = args ? args.parentSoftwareSource : undefined;
            resourceInputs["compartmentId"] = undefined /*out*/;
            resourceInputs["description"] = undefined /*out*/;
            resourceInputs["displayName"] = undefined /*out*/;
            resourceInputs["lastBoot"] = undefined /*out*/;
            resourceInputs["lastCheckin"] = undefined /*out*/;
            resourceInputs["osKernelVersion"] = undefined /*out*/;
            resourceInputs["osName"] = undefined /*out*/;
            resourceInputs["osVersion"] = undefined /*out*/;
            resourceInputs["status"] = undefined /*out*/;
            resourceInputs["updatesAvailable"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ManagedInstanceManagement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ManagedInstanceManagement resources.
 */
export interface ManagedInstanceManagementState {
    /**
     * (Updatable) list of child Software Sources attached to the Managed Instance
     */
    childSoftwareSources?: pulumi.Input<pulumi.Input<inputs.OsManagement.ManagedInstanceManagementChildSoftwareSource>[]>;
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
     * Time at which the instance last booted
     */
    lastBoot?: pulumi.Input<string>;
    /**
     * Time at which the instance last checked in
     */
    lastCheckin?: pulumi.Input<string>;
    /**
     * (Updatable) The ids of the managed instance groups of which this instance is a member.
     */
    managedInstanceGroups?: pulumi.Input<pulumi.Input<inputs.OsManagement.ManagedInstanceManagementManagedInstanceGroup>[]>;
    /**
     * OCID for the managed instance
     */
    managedInstanceId?: pulumi.Input<string>;
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
     * (Updatable) the parent (base) Software Source attached to the Managed Instance
     */
    parentSoftwareSource?: pulumi.Input<inputs.OsManagement.ManagedInstanceManagementParentSoftwareSource>;
    /**
     * status of the managed instance.
     */
    status?: pulumi.Input<string>;
    /**
     * Number of updates available to be installed
     */
    updatesAvailable?: pulumi.Input<number>;
}

/**
 * The set of arguments for constructing a ManagedInstanceManagement resource.
 */
export interface ManagedInstanceManagementArgs {
    /**
     * (Updatable) list of child Software Sources attached to the Managed Instance
     */
    childSoftwareSources?: pulumi.Input<pulumi.Input<inputs.OsManagement.ManagedInstanceManagementChildSoftwareSource>[]>;
    /**
     * (Updatable) The ids of the managed instance groups of which this instance is a member.
     */
    managedInstanceGroups?: pulumi.Input<pulumi.Input<inputs.OsManagement.ManagedInstanceManagementManagedInstanceGroup>[]>;
    /**
     * OCID for the managed instance
     */
    managedInstanceId: pulumi.Input<string>;
    /**
     * (Updatable) the parent (base) Software Source attached to the Managed Instance
     */
    parentSoftwareSource?: pulumi.Input<inputs.OsManagement.ManagedInstanceManagementParentSoftwareSource>;
}
