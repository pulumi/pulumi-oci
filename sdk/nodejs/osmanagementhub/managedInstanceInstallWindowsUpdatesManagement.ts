// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Managed Instance Install Windows Updates Management resource in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Installs Windows updates on the specified managed instance.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedInstanceInstallWindowsUpdatesManagement = new oci.osmanagementhub.ManagedInstanceInstallWindowsUpdatesManagement("test_managed_instance_install_windows_updates_management", {
 *     managedInstanceId: testManagedInstance.id,
 *     windowsUpdateNames: testWindowsUpdate.name,
 *     windowsUpdateTypes: managedInstanceInstallWindowsUpdatesManagementWindowsUpdateTypes,
 *     workRequestDetails: {
 *         description: managedInstanceInstallWindowsUpdatesManagementWorkRequestDetailsDescription,
 *         displayName: managedInstanceInstallWindowsUpdatesManagementWorkRequestDetailsDisplayName,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * ManagedInstanceInstallWindowsUpdatesManagement can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:OsManagementHub/managedInstanceInstallWindowsUpdatesManagement:ManagedInstanceInstallWindowsUpdatesManagement test_managed_instance_install_windows_updates_management "id"
 * ```
 */
export class ManagedInstanceInstallWindowsUpdatesManagement extends pulumi.CustomResource {
    /**
     * Get an existing ManagedInstanceInstallWindowsUpdatesManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ManagedInstanceInstallWindowsUpdatesManagementState, opts?: pulumi.CustomResourceOptions): ManagedInstanceInstallWindowsUpdatesManagement {
        return new ManagedInstanceInstallWindowsUpdatesManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:OsManagementHub/managedInstanceInstallWindowsUpdatesManagement:ManagedInstanceInstallWindowsUpdatesManagement';

    /**
     * Returns true if the given object is an instance of ManagedInstanceInstallWindowsUpdatesManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ManagedInstanceInstallWindowsUpdatesManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ManagedInstanceInstallWindowsUpdatesManagement.__pulumiType;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
     */
    public readonly managedInstanceId!: pulumi.Output<string>;
    /**
     * The list of Windows update unique identifiers.  Note that this is not an OCID, but is a unique identifier assigned by Microsoft. Example: '6981d463-cd91-4a26-b7c4-ea4ded9183ed'
     */
    public readonly windowsUpdateNames!: pulumi.Output<string[] | undefined>;
    /**
     * The types of Windows updates to be installed.
     */
    public readonly windowsUpdateTypes!: pulumi.Output<string[] | undefined>;
    /**
     * Provides the name and description of the job.
     */
    public readonly workRequestDetails!: pulumi.Output<outputs.OsManagementHub.ManagedInstanceInstallWindowsUpdatesManagementWorkRequestDetails>;

    /**
     * Create a ManagedInstanceInstallWindowsUpdatesManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ManagedInstanceInstallWindowsUpdatesManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ManagedInstanceInstallWindowsUpdatesManagementArgs | ManagedInstanceInstallWindowsUpdatesManagementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ManagedInstanceInstallWindowsUpdatesManagementState | undefined;
            resourceInputs["managedInstanceId"] = state ? state.managedInstanceId : undefined;
            resourceInputs["windowsUpdateNames"] = state ? state.windowsUpdateNames : undefined;
            resourceInputs["windowsUpdateTypes"] = state ? state.windowsUpdateTypes : undefined;
            resourceInputs["workRequestDetails"] = state ? state.workRequestDetails : undefined;
        } else {
            const args = argsOrState as ManagedInstanceInstallWindowsUpdatesManagementArgs | undefined;
            if ((!args || args.managedInstanceId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'managedInstanceId'");
            }
            resourceInputs["managedInstanceId"] = args ? args.managedInstanceId : undefined;
            resourceInputs["windowsUpdateNames"] = args ? args.windowsUpdateNames : undefined;
            resourceInputs["windowsUpdateTypes"] = args ? args.windowsUpdateTypes : undefined;
            resourceInputs["workRequestDetails"] = args ? args.workRequestDetails : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ManagedInstanceInstallWindowsUpdatesManagement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ManagedInstanceInstallWindowsUpdatesManagement resources.
 */
export interface ManagedInstanceInstallWindowsUpdatesManagementState {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
     */
    managedInstanceId?: pulumi.Input<string>;
    /**
     * The list of Windows update unique identifiers.  Note that this is not an OCID, but is a unique identifier assigned by Microsoft. Example: '6981d463-cd91-4a26-b7c4-ea4ded9183ed'
     */
    windowsUpdateNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The types of Windows updates to be installed.
     */
    windowsUpdateTypes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Provides the name and description of the job.
     */
    workRequestDetails?: pulumi.Input<inputs.OsManagementHub.ManagedInstanceInstallWindowsUpdatesManagementWorkRequestDetails>;
}

/**
 * The set of arguments for constructing a ManagedInstanceInstallWindowsUpdatesManagement resource.
 */
export interface ManagedInstanceInstallWindowsUpdatesManagementArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
     */
    managedInstanceId: pulumi.Input<string>;
    /**
     * The list of Windows update unique identifiers.  Note that this is not an OCID, but is a unique identifier assigned by Microsoft. Example: '6981d463-cd91-4a26-b7c4-ea4ded9183ed'
     */
    windowsUpdateNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The types of Windows updates to be installed.
     */
    windowsUpdateTypes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Provides the name and description of the job.
     */
    workRequestDetails?: pulumi.Input<inputs.OsManagementHub.ManagedInstanceInstallWindowsUpdatesManagementWorkRequestDetails>;
}
