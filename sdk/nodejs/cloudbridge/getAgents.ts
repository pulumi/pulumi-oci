// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Agents in Oracle Cloud Infrastructure Cloud Bridge service.
 *
 * Returns a list of Agents.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAgents = oci.CloudBridge.getAgents({
 *     compartmentId: _var.compartment_id,
 *     agentId: oci_cloud_bridge_agent.test_agent.id,
 *     displayName: _var.agent_display_name,
 *     environmentId: oci_cloud_bridge_environment.test_environment.id,
 *     state: _var.agent_state,
 * });
 * ```
 */
export function getAgents(args: GetAgentsArgs, opts?: pulumi.InvokeOptions): Promise<GetAgentsResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:CloudBridge/getAgents:getAgents", {
        "agentId": args.agentId,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "environmentId": args.environmentId,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getAgents.
 */
export interface GetAgentsArgs {
    /**
     * A filter to return only resources that match the given Agent ID.
     */
    agentId?: string;
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    /**
     * A filter to return only resources that match the given environment ID.
     */
    environmentId?: string;
    filters?: inputs.CloudBridge.GetAgentsFilter[];
    /**
     * A filter to return only resources their lifecycleState matches the given lifecycleState.
     */
    state?: string;
}

/**
 * A collection of values returned by getAgents.
 */
export interface GetAgentsResult {
    /**
     * The list of agent_collection.
     */
    readonly agentCollections: outputs.CloudBridge.GetAgentsAgentCollection[];
    /**
     * Agent identifier.
     */
    readonly agentId?: string;
    /**
     * Compartment identifier.
     */
    readonly compartmentId: string;
    /**
     * Agent identifier, can be renamed.
     */
    readonly displayName?: string;
    /**
     * Environment identifier.
     */
    readonly environmentId?: string;
    readonly filters?: outputs.CloudBridge.GetAgentsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the Agent.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Agents in Oracle Cloud Infrastructure Cloud Bridge service.
 *
 * Returns a list of Agents.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAgents = oci.CloudBridge.getAgents({
 *     compartmentId: _var.compartment_id,
 *     agentId: oci_cloud_bridge_agent.test_agent.id,
 *     displayName: _var.agent_display_name,
 *     environmentId: oci_cloud_bridge_environment.test_environment.id,
 *     state: _var.agent_state,
 * });
 * ```
 */
export function getAgentsOutput(args: GetAgentsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetAgentsResult> {
    return pulumi.output(args).apply((a: any) => getAgents(a, opts))
}

/**
 * A collection of arguments for invoking getAgents.
 */
export interface GetAgentsOutputArgs {
    /**
     * A filter to return only resources that match the given Agent ID.
     */
    agentId?: pulumi.Input<string>;
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given environment ID.
     */
    environmentId?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.CloudBridge.GetAgentsFilterArgs>[]>;
    /**
     * A filter to return only resources their lifecycleState matches the given lifecycleState.
     */
    state?: pulumi.Input<string>;
}