// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Instance Agent Plugins in Oracle Cloud Infrastructure Compute Instance Agent service.
 *
 * The API to get one or more plugin information.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInstanceAgentPlugins = oci.ComputeInstanceAgent.getInstanceAgentPlugins({
 *     instanceagentId: oci_computeinstanceagent_instanceagent.test_instanceagent.id,
 *     name: _var.instance_agent_plugin_name,
 *     status: _var.instance_agent_plugin_status,
 * });
 * ```
 */
export function getInstanceAgentPlugins(args: GetInstanceAgentPluginsArgs, opts?: pulumi.InvokeOptions): Promise<GetInstanceAgentPluginsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:ComputeInstanceAgent/getInstanceAgentPlugins:getInstanceAgentPlugins", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "instanceagentId": args.instanceagentId,
        "name": args.name,
        "status": args.status,
    }, opts);
}

/**
 * A collection of arguments for invoking getInstanceAgentPlugins.
 */
export interface GetInstanceAgentPluginsArgs {
    compartmentId: string;
    filters?: inputs.ComputeInstanceAgent.GetInstanceAgentPluginsFilter[];
    /**
     * The OCID of the instance.
     */
    instanceagentId: string;
    /**
     * The plugin name
     */
    name?: string;
    /**
     * The plugin status
     */
    status?: string;
}

/**
 * A collection of values returned by getInstanceAgentPlugins.
 */
export interface GetInstanceAgentPluginsResult {
    readonly compartmentId: string;
    readonly filters?: outputs.ComputeInstanceAgent.GetInstanceAgentPluginsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of instance_agent_plugins.
     */
    readonly instanceAgentPlugins: outputs.ComputeInstanceAgent.GetInstanceAgentPluginsInstanceAgentPlugin[];
    readonly instanceagentId: string;
    /**
     * The plugin name
     */
    readonly name?: string;
    /**
     * The plugin status Specified the plugin state on the instance * `RUNNING` - The plugin is in running state * `STOPPED` - The plugin is in stopped state * `NOT_SUPPORTED` - The plugin is not supported on this platform * `INVALID` - The plugin state is not recognizable by the service
     */
    readonly status?: string;
}

export function getInstanceAgentPluginsOutput(args: GetInstanceAgentPluginsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetInstanceAgentPluginsResult> {
    return pulumi.output(args).apply(a => getInstanceAgentPlugins(a, opts))
}

/**
 * A collection of arguments for invoking getInstanceAgentPlugins.
 */
export interface GetInstanceAgentPluginsOutputArgs {
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.ComputeInstanceAgent.GetInstanceAgentPluginsFilterArgs>[]>;
    /**
     * The OCID of the instance.
     */
    instanceagentId: pulumi.Input<string>;
    /**
     * The plugin name
     */
    name?: pulumi.Input<string>;
    /**
     * The plugin status
     */
    status?: pulumi.Input<string>;
}