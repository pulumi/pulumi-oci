// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Config resource in Oracle Cloud Infrastructure Stack Monitoring service.
 *
 * Creates a configuration item, for example to define
 * whether resources of a specific type should be discovered automatically.
 *
 * For example, when a new Management Agent gets registered in a certain compartment,
 * this Management Agent can potentially get promoted to a HOST resource.
 * The configuration item will determine if HOST resources in the selected compartment will be
 * discovered automatically.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testConfig = new oci.stackmonitoring.Config("testConfig", {
 *     compartmentId: _var.compartment_id,
 *     configType: _var.config_config_type,
 *     isEnabled: _var.config_is_enabled,
 *     resourceType: _var.config_resource_type,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     displayName: _var.config_display_name,
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * Configs can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:StackMonitoring/config:Config test_config "id"
 * ```
 */
export class Config extends pulumi.CustomResource {
    /**
     * Get an existing Config resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ConfigState, opts?: pulumi.CustomResourceOptions): Config {
        return new Config(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:StackMonitoring/config:Config';

    /**
     * Returns true if the given object is an instance of Config.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Config {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Config.__pulumiType;
    }

    /**
     * (Updatable) Compartment in which the configuration is created.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The type of configuration. The only valid value is `"AUTO_PROMOTE"`.
     */
    public readonly configType!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The display name of the configuration.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) True if automatic promotion is enabled, false if it is not enabled.
     */
    public readonly isEnabled!: pulumi.Output<boolean>;
    /**
     * The type of resource to configure for automatic promotion. The only valid value is `"HOST"`.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly resourceType!: pulumi.Output<string>;
    /**
     * The current state of the configuration.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The time the configuration was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time the Config was updated.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a Config resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ConfigArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ConfigArgs | ConfigState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ConfigState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["configType"] = state ? state.configType : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["isEnabled"] = state ? state.isEnabled : undefined;
            resourceInputs["resourceType"] = state ? state.resourceType : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as ConfigArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.configType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'configType'");
            }
            if ((!args || args.isEnabled === undefined) && !opts.urn) {
                throw new Error("Missing required property 'isEnabled'");
            }
            if ((!args || args.resourceType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'resourceType'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["configType"] = args ? args.configType : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["isEnabled"] = args ? args.isEnabled : undefined;
            resourceInputs["resourceType"] = args ? args.resourceType : undefined;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(Config.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Config resources.
 */
export interface ConfigState {
    /**
     * (Updatable) Compartment in which the configuration is created.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The type of configuration. The only valid value is `"AUTO_PROMOTE"`.
     */
    configType?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The display name of the configuration.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) True if automatic promotion is enabled, false if it is not enabled.
     */
    isEnabled?: pulumi.Input<boolean>;
    /**
     * The type of resource to configure for automatic promotion. The only valid value is `"HOST"`.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    resourceType?: pulumi.Input<string>;
    /**
     * The current state of the configuration.
     */
    state?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The time the configuration was created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time the Config was updated.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Config resource.
 */
export interface ConfigArgs {
    /**
     * (Updatable) Compartment in which the configuration is created.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The type of configuration. The only valid value is `"AUTO_PROMOTE"`.
     */
    configType: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The display name of the configuration.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) True if automatic promotion is enabled, false if it is not enabled.
     */
    isEnabled: pulumi.Input<boolean>;
    /**
     * The type of resource to configure for automatic promotion. The only valid value is `"HOST"`.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    resourceType: pulumi.Input<string>;
}