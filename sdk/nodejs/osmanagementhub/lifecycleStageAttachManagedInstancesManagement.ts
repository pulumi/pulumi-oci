// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Lifecycle Stage Attach Managed Instances Management resource in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Attaches (adds) managed instances to a lifecycle stage. Once added, you can apply operations to all managed instances in the lifecycle stage.
 *
 * ## Import
 *
 * LifecycleStageAttachManagedInstancesManagement can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:OsManagementHub/lifecycleStageAttachManagedInstancesManagement:LifecycleStageAttachManagedInstancesManagement test_lifecycle_stage_attach_managed_instances_management "id"
 * ```
 */
export class LifecycleStageAttachManagedInstancesManagement extends pulumi.CustomResource {
    /**
     * Get an existing LifecycleStageAttachManagedInstancesManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: LifecycleStageAttachManagedInstancesManagementState, opts?: pulumi.CustomResourceOptions): LifecycleStageAttachManagedInstancesManagement {
        return new LifecycleStageAttachManagedInstancesManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:OsManagementHub/lifecycleStageAttachManagedInstancesManagement:LifecycleStageAttachManagedInstancesManagement';

    /**
     * Returns true if the given object is an instance of LifecycleStageAttachManagedInstancesManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is LifecycleStageAttachManagedInstancesManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === LifecycleStageAttachManagedInstancesManagement.__pulumiType;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
     */
    public readonly lifecycleStageId!: pulumi.Output<string>;
    /**
     * The details about the managed instances.
     */
    public readonly managedInstanceDetails!: pulumi.Output<outputs.OsManagementHub.LifecycleStageAttachManagedInstancesManagementManagedInstanceDetails>;

    /**
     * Create a LifecycleStageAttachManagedInstancesManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: LifecycleStageAttachManagedInstancesManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: LifecycleStageAttachManagedInstancesManagementArgs | LifecycleStageAttachManagedInstancesManagementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as LifecycleStageAttachManagedInstancesManagementState | undefined;
            resourceInputs["lifecycleStageId"] = state ? state.lifecycleStageId : undefined;
            resourceInputs["managedInstanceDetails"] = state ? state.managedInstanceDetails : undefined;
        } else {
            const args = argsOrState as LifecycleStageAttachManagedInstancesManagementArgs | undefined;
            if ((!args || args.lifecycleStageId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'lifecycleStageId'");
            }
            if ((!args || args.managedInstanceDetails === undefined) && !opts.urn) {
                throw new Error("Missing required property 'managedInstanceDetails'");
            }
            resourceInputs["lifecycleStageId"] = args ? args.lifecycleStageId : undefined;
            resourceInputs["managedInstanceDetails"] = args ? args.managedInstanceDetails : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(LifecycleStageAttachManagedInstancesManagement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering LifecycleStageAttachManagedInstancesManagement resources.
 */
export interface LifecycleStageAttachManagedInstancesManagementState {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
     */
    lifecycleStageId?: pulumi.Input<string>;
    /**
     * The details about the managed instances.
     */
    managedInstanceDetails?: pulumi.Input<inputs.OsManagementHub.LifecycleStageAttachManagedInstancesManagementManagedInstanceDetails>;
}

/**
 * The set of arguments for constructing a LifecycleStageAttachManagedInstancesManagement resource.
 */
export interface LifecycleStageAttachManagedInstancesManagementArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the lifecycle stage.
     */
    lifecycleStageId: pulumi.Input<string>;
    /**
     * The details about the managed instances.
     */
    managedInstanceDetails: pulumi.Input<inputs.OsManagementHub.LifecycleStageAttachManagedInstancesManagementManagedInstanceDetails>;
}
