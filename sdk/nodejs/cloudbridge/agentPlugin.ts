// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Agent Plugin resource in Oracle Cloud Infrastructure Cloud Bridge service.
 *
 * Updates the plugin.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAgentPlugin = new oci.cloudbridge.AgentPlugin("testAgentPlugin", {
 *     agentId: oci_cloud_bridge_agent.test_agent.id,
 *     pluginName: _var.agent_plugin_plugin_name,
 *     desiredState: _var.agent_plugin_desired_state,
 * });
 * ```
 *
 * ## Import
 *
 * AgentPlugins can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:CloudBridge/agentPlugin:AgentPlugin test_agent_plugin "agents/{agentId}/plugins/{pluginName}"
 * ```
 */
export class AgentPlugin extends pulumi.CustomResource {
    /**
     * Get an existing AgentPlugin resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AgentPluginState, opts?: pulumi.CustomResourceOptions): AgentPlugin {
        return new AgentPlugin(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:CloudBridge/agentPlugin:AgentPlugin';

    /**
     * Returns true if the given object is an instance of AgentPlugin.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AgentPlugin {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AgentPlugin.__pulumiType;
    }

    /**
     * Unique Agent identifier path parameter.
     */
    public readonly agentId!: pulumi.Output<string>;
    /**
     * The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    public /*out*/ readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) State to which the customer wants the plugin to move to.
     */
    public readonly desiredState!: pulumi.Output<string>;
    /**
     * The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public /*out*/ readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * Plugin identifier, which can be renamed.
     */
    public /*out*/ readonly name!: pulumi.Output<string>;
    /**
     * Unique plugin identifier path parameter.
     */
    public readonly pluginName!: pulumi.Output<string>;
    /**
     * Plugin version.
     */
    public /*out*/ readonly pluginVersion!: pulumi.Output<string>;
    /**
     * The current state of the plugin.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The time when the Agent was created. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time when the Agent was updated. An RFC3339 formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;

    /**
     * Create a AgentPlugin resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: AgentPluginArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AgentPluginArgs | AgentPluginState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AgentPluginState | undefined;
            resourceInputs["agentId"] = state ? state.agentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["desiredState"] = state ? state.desiredState : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["pluginName"] = state ? state.pluginName : undefined;
            resourceInputs["pluginVersion"] = state ? state.pluginVersion : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
        } else {
            const args = argsOrState as AgentPluginArgs | undefined;
            if ((!args || args.agentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'agentId'");
            }
            if ((!args || args.pluginName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'pluginName'");
            }
            resourceInputs["agentId"] = args ? args.agentId : undefined;
            resourceInputs["desiredState"] = args ? args.desiredState : undefined;
            resourceInputs["pluginName"] = args ? args.pluginName : undefined;
            resourceInputs["definedTags"] = undefined /*out*/;
            resourceInputs["freeformTags"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["name"] = undefined /*out*/;
            resourceInputs["pluginVersion"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(AgentPlugin.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AgentPlugin resources.
 */
export interface AgentPluginState {
    /**
     * Unique Agent identifier path parameter.
     */
    agentId?: pulumi.Input<string>;
    /**
     * The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) State to which the customer wants the plugin to move to.
     */
    desiredState?: pulumi.Input<string>;
    /**
     * The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace/scope. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * A message describing the current state in more detail. For example, it can be used to provide actionable information for a resource in Failed state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * Plugin identifier, which can be renamed.
     */
    name?: pulumi.Input<string>;
    /**
     * Unique plugin identifier path parameter.
     */
    pluginName?: pulumi.Input<string>;
    /**
     * Plugin version.
     */
    pluginVersion?: pulumi.Input<string>;
    /**
     * The current state of the plugin.
     */
    state?: pulumi.Input<string>;
    /**
     * The system tags associated with this resource, if any. The system tags are set by Oracle cloud infrastructure services. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The time when the Agent was created. An RFC3339 formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time when the Agent was updated. An RFC3339 formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AgentPlugin resource.
 */
export interface AgentPluginArgs {
    /**
     * Unique Agent identifier path parameter.
     */
    agentId: pulumi.Input<string>;
    /**
     * (Updatable) State to which the customer wants the plugin to move to.
     */
    desiredState?: pulumi.Input<string>;
    /**
     * Unique plugin identifier path parameter.
     */
    pluginName: pulumi.Input<string>;
}