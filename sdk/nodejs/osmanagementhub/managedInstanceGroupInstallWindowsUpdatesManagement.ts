// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Managed Instance Group Install Windows Updates Management resource in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Installs Windows updates on each managed instance in the managed instance group.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedInstanceGroupInstallWindowsUpdatesManagement = new oci.osmanagementhub.ManagedInstanceGroupInstallWindowsUpdatesManagement("test_managed_instance_group_install_windows_updates_management", {
 *     managedInstanceGroupId: testManagedInstanceGroup.id,
 *     windowsUpdateTypes: managedInstanceGroupInstallWindowsUpdatesManagementWindowsUpdateTypes,
 *     workRequestDetails: {
 *         description: managedInstanceGroupInstallWindowsUpdatesManagementWorkRequestDetailsDescription,
 *         displayName: managedInstanceGroupInstallWindowsUpdatesManagementWorkRequestDetailsDisplayName,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * ManagedInstanceGroupInstallWindowsUpdatesManagement can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:OsManagementHub/managedInstanceGroupInstallWindowsUpdatesManagement:ManagedInstanceGroupInstallWindowsUpdatesManagement test_managed_instance_group_install_windows_updates_management "id"
 * ```
 */
export class ManagedInstanceGroupInstallWindowsUpdatesManagement extends pulumi.CustomResource {
    /**
     * Get an existing ManagedInstanceGroupInstallWindowsUpdatesManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ManagedInstanceGroupInstallWindowsUpdatesManagementState, opts?: pulumi.CustomResourceOptions): ManagedInstanceGroupInstallWindowsUpdatesManagement {
        return new ManagedInstanceGroupInstallWindowsUpdatesManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:OsManagementHub/managedInstanceGroupInstallWindowsUpdatesManagement:ManagedInstanceGroupInstallWindowsUpdatesManagement';

    /**
     * Returns true if the given object is an instance of ManagedInstanceGroupInstallWindowsUpdatesManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ManagedInstanceGroupInstallWindowsUpdatesManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ManagedInstanceGroupInstallWindowsUpdatesManagement.__pulumiType;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
     */
    public readonly managedInstanceGroupId!: pulumi.Output<string>;
    /**
     * The type of Windows updates to be applied.
     */
    public readonly windowsUpdateTypes!: pulumi.Output<string[]>;
    /**
     * Provides the name and description of the job.
     */
    public readonly workRequestDetails!: pulumi.Output<outputs.OsManagementHub.ManagedInstanceGroupInstallWindowsUpdatesManagementWorkRequestDetails>;

    /**
     * Create a ManagedInstanceGroupInstallWindowsUpdatesManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ManagedInstanceGroupInstallWindowsUpdatesManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ManagedInstanceGroupInstallWindowsUpdatesManagementArgs | ManagedInstanceGroupInstallWindowsUpdatesManagementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ManagedInstanceGroupInstallWindowsUpdatesManagementState | undefined;
            resourceInputs["managedInstanceGroupId"] = state ? state.managedInstanceGroupId : undefined;
            resourceInputs["windowsUpdateTypes"] = state ? state.windowsUpdateTypes : undefined;
            resourceInputs["workRequestDetails"] = state ? state.workRequestDetails : undefined;
        } else {
            const args = argsOrState as ManagedInstanceGroupInstallWindowsUpdatesManagementArgs | undefined;
            if ((!args || args.managedInstanceGroupId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'managedInstanceGroupId'");
            }
            if ((!args || args.windowsUpdateTypes === undefined) && !opts.urn) {
                throw new Error("Missing required property 'windowsUpdateTypes'");
            }
            resourceInputs["managedInstanceGroupId"] = args ? args.managedInstanceGroupId : undefined;
            resourceInputs["windowsUpdateTypes"] = args ? args.windowsUpdateTypes : undefined;
            resourceInputs["workRequestDetails"] = args ? args.workRequestDetails : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ManagedInstanceGroupInstallWindowsUpdatesManagement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ManagedInstanceGroupInstallWindowsUpdatesManagement resources.
 */
export interface ManagedInstanceGroupInstallWindowsUpdatesManagementState {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
     */
    managedInstanceGroupId?: pulumi.Input<string>;
    /**
     * The type of Windows updates to be applied.
     */
    windowsUpdateTypes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Provides the name and description of the job.
     */
    workRequestDetails?: pulumi.Input<inputs.OsManagementHub.ManagedInstanceGroupInstallWindowsUpdatesManagementWorkRequestDetails>;
}

/**
 * The set of arguments for constructing a ManagedInstanceGroupInstallWindowsUpdatesManagement resource.
 */
export interface ManagedInstanceGroupInstallWindowsUpdatesManagementArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
     */
    managedInstanceGroupId: pulumi.Input<string>;
    /**
     * The type of Windows updates to be applied.
     */
    windowsUpdateTypes: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Provides the name and description of the job.
     */
    workRequestDetails?: pulumi.Input<inputs.OsManagementHub.ManagedInstanceGroupInstallWindowsUpdatesManagementWorkRequestDetails>;
}
