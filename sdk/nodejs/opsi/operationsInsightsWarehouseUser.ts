// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Operations Insights Warehouse User resource in Oracle Cloud Infrastructure Opsi service.
 *
 * Create a Operations Insights Warehouse user resource for the tenant in Operations Insights.
 * This resource will be created in root compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOperationsInsightsWarehouseUser = new oci.opsi.OperationsInsightsWarehouseUser("test_operations_insights_warehouse_user", {
 *     compartmentId: compartmentId,
 *     connectionPassword: operationsInsightsWarehouseUserConnectionPassword,
 *     isAwrDataAccess: operationsInsightsWarehouseUserIsAwrDataAccess,
 *     name: operationsInsightsWarehouseUserName,
 *     operationsInsightsWarehouseId: testOperationsInsightsWarehouse.id,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     isEmDataAccess: operationsInsightsWarehouseUserIsEmDataAccess,
 *     isOpsiDataAccess: operationsInsightsWarehouseUserIsOpsiDataAccess,
 * });
 * ```
 *
 * ## Import
 *
 * OperationsInsightsWarehouseUsers can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Opsi/operationsInsightsWarehouseUser:OperationsInsightsWarehouseUser test_operations_insights_warehouse_user "id"
 * ```
 */
export class OperationsInsightsWarehouseUser extends pulumi.CustomResource {
    /**
     * Get an existing OperationsInsightsWarehouseUser resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: OperationsInsightsWarehouseUserState, opts?: pulumi.CustomResourceOptions): OperationsInsightsWarehouseUser {
        return new OperationsInsightsWarehouseUser(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Opsi/operationsInsightsWarehouseUser:OperationsInsightsWarehouseUser';

    /**
     * Returns true if the given object is an instance of OperationsInsightsWarehouseUser.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is OperationsInsightsWarehouseUser {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === OperationsInsightsWarehouseUser.__pulumiType;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) User provided connection password for the AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
     */
    public readonly connectionPassword!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) Indicate whether user has access to AWR data.
     */
    public readonly isAwrDataAccess!: pulumi.Output<boolean>;
    /**
     * (Updatable) Indicate whether user has access to EM data.
     */
    public readonly isEmDataAccess!: pulumi.Output<boolean>;
    /**
     * (Updatable) Indicate whether user has access to OPSI data.
     */
    public readonly isOpsiDataAccess!: pulumi.Output<boolean>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * Username for schema which would have access to AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * OPSI Warehouse OCID
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly operationsInsightsWarehouseId!: pulumi.Output<string>;
    /**
     * Possible lifecycle states
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The time at which the resource was first created. An RFC3339 formatted datetime string
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time at which the resource was last updated. An RFC3339 formatted datetime string
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a OperationsInsightsWarehouseUser resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: OperationsInsightsWarehouseUserArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: OperationsInsightsWarehouseUserArgs | OperationsInsightsWarehouseUserState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as OperationsInsightsWarehouseUserState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["connectionPassword"] = state ? state.connectionPassword : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["isAwrDataAccess"] = state ? state.isAwrDataAccess : undefined;
            resourceInputs["isEmDataAccess"] = state ? state.isEmDataAccess : undefined;
            resourceInputs["isOpsiDataAccess"] = state ? state.isOpsiDataAccess : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["operationsInsightsWarehouseId"] = state ? state.operationsInsightsWarehouseId : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as OperationsInsightsWarehouseUserArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.connectionPassword === undefined) && !opts.urn) {
                throw new Error("Missing required property 'connectionPassword'");
            }
            if ((!args || args.isAwrDataAccess === undefined) && !opts.urn) {
                throw new Error("Missing required property 'isAwrDataAccess'");
            }
            if ((!args || args.operationsInsightsWarehouseId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'operationsInsightsWarehouseId'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["connectionPassword"] = args?.connectionPassword ? pulumi.secret(args.connectionPassword) : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["isAwrDataAccess"] = args ? args.isAwrDataAccess : undefined;
            resourceInputs["isEmDataAccess"] = args ? args.isEmDataAccess : undefined;
            resourceInputs["isOpsiDataAccess"] = args ? args.isOpsiDataAccess : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["operationsInsightsWarehouseId"] = args ? args.operationsInsightsWarehouseId : undefined;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        const secretOpts = { additionalSecretOutputs: ["connectionPassword"] };
        opts = pulumi.mergeOptions(opts, secretOpts);
        super(OperationsInsightsWarehouseUser.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering OperationsInsightsWarehouseUser resources.
 */
export interface OperationsInsightsWarehouseUserState {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) User provided connection password for the AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
     */
    connectionPassword?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Indicate whether user has access to AWR data.
     */
    isAwrDataAccess?: pulumi.Input<boolean>;
    /**
     * (Updatable) Indicate whether user has access to EM data.
     */
    isEmDataAccess?: pulumi.Input<boolean>;
    /**
     * (Updatable) Indicate whether user has access to OPSI data.
     */
    isOpsiDataAccess?: pulumi.Input<boolean>;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * Username for schema which would have access to AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
     */
    name?: pulumi.Input<string>;
    /**
     * OPSI Warehouse OCID
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    operationsInsightsWarehouseId?: pulumi.Input<string>;
    /**
     * Possible lifecycle states
     */
    state?: pulumi.Input<string>;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The time at which the resource was first created. An RFC3339 formatted datetime string
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time at which the resource was last updated. An RFC3339 formatted datetime string
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a OperationsInsightsWarehouseUser resource.
 */
export interface OperationsInsightsWarehouseUserArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) User provided connection password for the AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
     */
    connectionPassword: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) Indicate whether user has access to AWR data.
     */
    isAwrDataAccess: pulumi.Input<boolean>;
    /**
     * (Updatable) Indicate whether user has access to EM data.
     */
    isEmDataAccess?: pulumi.Input<boolean>;
    /**
     * (Updatable) Indicate whether user has access to OPSI data.
     */
    isOpsiDataAccess?: pulumi.Input<boolean>;
    /**
     * Username for schema which would have access to AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
     */
    name?: pulumi.Input<string>;
    /**
     * OPSI Warehouse OCID
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    operationsInsightsWarehouseId: pulumi.Input<string>;
}
