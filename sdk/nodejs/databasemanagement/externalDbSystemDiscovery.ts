// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the External Db System Discovery resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Creates an external DB system discovery resource and initiates the discovery process.
 *
 *   Patches the external DB system discovery specified by `externalDbSystemDiscoveryId`.
 *
 * ## Import
 *
 * ExternalDbSystemDiscoveries can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:DatabaseManagement/externalDbSystemDiscovery:ExternalDbSystemDiscovery test_external_db_system_discovery "id"
 * ```
 */
export class ExternalDbSystemDiscovery extends pulumi.CustomResource {
    /**
     * Get an existing ExternalDbSystemDiscovery resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ExternalDbSystemDiscoveryState, opts?: pulumi.CustomResourceOptions): ExternalDbSystemDiscovery {
        return new ExternalDbSystemDiscovery(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:DatabaseManagement/externalDbSystemDiscovery:ExternalDbSystemDiscovery';

    /**
     * Returns true if the given object is an instance of ExternalDbSystemDiscovery.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ExternalDbSystemDiscovery {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ExternalDbSystemDiscovery.__pulumiType;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system discovery.
     */
    public readonly agentId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The list of DB system components that were found in the DB system discovery.
     */
    public /*out*/ readonly discoveredComponents!: pulumi.Output<outputs.DatabaseManagement.ExternalDbSystemDiscoveryDiscoveredComponent[]>;
    /**
     * (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
     */
    public readonly displayName!: pulumi.Output<string>;
    public /*out*/ readonly externalDbSystemDiscoveryId!: pulumi.Output<string>;
    /**
     * The directory in which Oracle Grid Infrastructure is installed.
     */
    public /*out*/ readonly gridHome!: pulumi.Output<string>;
    /**
     * Additional information about the current lifecycle state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * (Updatable)
     */
    public readonly patchOperations!: pulumi.Output<outputs.DatabaseManagement.ExternalDbSystemDiscoveryPatchOperation[] | undefined>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the existing Oracle Cloud Infrastructure resource matching the discovered DB system.
     */
    public /*out*/ readonly resourceId!: pulumi.Output<string>;
    /**
     * The current lifecycle state of the external DB system discovery resource.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the external DB system discovery was created.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The date and time the external DB system discovery was last updated.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a ExternalDbSystemDiscovery resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ExternalDbSystemDiscoveryArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ExternalDbSystemDiscoveryArgs | ExternalDbSystemDiscoveryState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ExternalDbSystemDiscoveryState | undefined;
            resourceInputs["agentId"] = state ? state.agentId : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["discoveredComponents"] = state ? state.discoveredComponents : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["externalDbSystemDiscoveryId"] = state ? state.externalDbSystemDiscoveryId : undefined;
            resourceInputs["gridHome"] = state ? state.gridHome : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["patchOperations"] = state ? state.patchOperations : undefined;
            resourceInputs["resourceId"] = state ? state.resourceId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as ExternalDbSystemDiscoveryArgs | undefined;
            if ((!args || args.agentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'agentId'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            resourceInputs["agentId"] = args ? args.agentId : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["patchOperations"] = args ? args.patchOperations : undefined;
            resourceInputs["discoveredComponents"] = undefined /*out*/;
            resourceInputs["externalDbSystemDiscoveryId"] = undefined /*out*/;
            resourceInputs["gridHome"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["resourceId"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ExternalDbSystemDiscovery.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ExternalDbSystemDiscovery resources.
 */
export interface ExternalDbSystemDiscoveryState {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system discovery.
     */
    agentId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The list of DB system components that were found in the DB system discovery.
     */
    discoveredComponents?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.ExternalDbSystemDiscoveryDiscoveredComponent>[]>;
    /**
     * (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
     */
    displayName?: pulumi.Input<string>;
    externalDbSystemDiscoveryId?: pulumi.Input<string>;
    /**
     * The directory in which Oracle Grid Infrastructure is installed.
     */
    gridHome?: pulumi.Input<string>;
    /**
     * Additional information about the current lifecycle state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * (Updatable)
     */
    patchOperations?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.ExternalDbSystemDiscoveryPatchOperation>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the existing Oracle Cloud Infrastructure resource matching the discovered DB system.
     */
    resourceId?: pulumi.Input<string>;
    /**
     * The current lifecycle state of the external DB system discovery resource.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the external DB system discovery was created.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The date and time the external DB system discovery was last updated.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ExternalDbSystemDiscovery resource.
 */
export interface ExternalDbSystemDiscoveryArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used for the external DB system discovery.
     */
    agentId: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) The user-friendly name for the DB system. The name does not have to be unique.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable)
     */
    patchOperations?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.ExternalDbSystemDiscoveryPatchOperation>[]>;
}