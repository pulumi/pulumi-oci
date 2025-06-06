// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Management Agents in Oracle Cloud Infrastructure Management Agent service.
 *
 * Returns a list of Management Agents.
 * If no explicit page size limit is specified, it will default to 1000 when compartmentIdInSubtree is true and 5000 otherwise.
 * The response is limited to maximum 1000 records when compartmentIdInSubtree is true.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagementAgents = oci.ManagementAgent.getManagementAgents({
 *     compartmentId: compartmentId,
 *     accessLevel: managementAgentAccessLevel,
 *     availabilityStatus: managementAgentAvailabilityStatus,
 *     compartmentIdInSubtree: managementAgentCompartmentIdInSubtree,
 *     dataSourceNames: testManagementAgentDataSource.name,
 *     dataSourceType: managementAgentDataSourceType,
 *     displayName: managementAgentDisplayName,
 *     gatewayIds: testGateway.id,
 *     hostId: testHost.id,
 *     waitForHostId: 10,
 *     installType: managementAgentInstallType,
 *     isCustomerDeployed: managementAgentIsCustomerDeployed,
 *     platformTypes: managementAgentPlatformType,
 *     pluginNames: managementAgentPluginName,
 *     state: managementAgentState,
 *     versions: managementAgentVersion,
 * });
 * ```
 */
export function getManagementAgents(args: GetManagementAgentsArgs, opts?: pulumi.InvokeOptions): Promise<GetManagementAgentsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ManagementAgent/getManagementAgents:getManagementAgents", {
        "accessLevel": args.accessLevel,
        "availabilityStatus": args.availabilityStatus,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "dataSourceNames": args.dataSourceNames,
        "dataSourceType": args.dataSourceType,
        "displayName": args.displayName,
        "filters": args.filters,
        "gatewayIds": args.gatewayIds,
        "hostId": args.hostId,
        "installType": args.installType,
        "isCustomerDeployed": args.isCustomerDeployed,
        "platformTypes": args.platformTypes,
        "pluginNames": args.pluginNames,
        "state": args.state,
        "versions": args.versions,
        "waitForHostId": args.waitForHostId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagementAgents.
 */
export interface GetManagementAgentsArgs {
    /**
     * When the value is "ACCESSIBLE", insufficient permissions for a compartment will filter out resources in that compartment without rejecting the request.
     */
    accessLevel?: string;
    /**
     * Filter to return only Management Agents in the particular availability status.
     */
    availabilityStatus?: string;
    /**
     * The OCID of the compartment to which a request will be scoped.
     */
    compartmentId: string;
    /**
     * if set to true then it fetches resources for all compartments where user has access to else only on the compartment specified.
     */
    compartmentIdInSubtree?: boolean;
    /**
     * Unique name of the dataSource.
     */
    dataSourceNames?: string[];
    /**
     * The type of the dataSource.
     */
    dataSourceType?: string;
    /**
     * Filter to return only Management Agents having the particular display name.
     */
    displayName?: string;
    filters?: inputs.ManagementAgent.GetManagementAgentsFilter[];
    /**
     * Filter to return only results having the particular gatewayId.
     */
    gatewayIds?: string[];
    /**
     * Filter to return only Management Agents having the particular agent host id.
     */
    hostId?: string;
    /**
     * A filter to return either agents or gateway types depending upon install type selected by user. By default both install type will be returned.
     */
    installType?: string;
    /**
     * true, if the agent image is manually downloaded and installed. false, if the agent is deployed as a plugin in Oracle Cloud Agent.
     */
    isCustomerDeployed?: boolean;
    /**
     * Array of PlatformTypes to return only results having the particular platform types. Example: ["LINUX"]
     */
    platformTypes?: string[];
    /**
     * Array of pluginName to return only Management Agents having the particular Plugins installed. A special pluginName of 'None' can be provided and this will return only Management Agents having no plugin installed. Example: ["PluginA"]
     */
    pluginNames?: string[];
    /**
     * Filter to return only Management Agents in the particular lifecycle state.
     */
    state?: string;
    /**
     * Array of versions to return only Management Agents having the particular agent versions. Example: ["202020.0101","210201.0513"]
     */
    versions?: string[];
    /**
     * When hostId argument is set, the data source will wait for the given period of time (in minutes) for this hostId to become available. This can be used when compute instance with Management Agent has been recently created.
     */
    waitForHostId?: number;
}

/**
 * A collection of values returned by getManagementAgents.
 */
export interface GetManagementAgentsResult {
    readonly accessLevel?: string;
    /**
     * The current availability status of managementAgent
     */
    readonly availabilityStatus?: string;
    /**
     * Compartment Identifier
     */
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    readonly dataSourceNames?: string[];
    readonly dataSourceType?: string;
    /**
     * Management Agent Name
     */
    readonly displayName?: string;
    readonly filters?: outputs.ManagementAgent.GetManagementAgentsFilter[];
    readonly gatewayIds?: string[];
    /**
     * Host resource ocid
     */
    readonly hostId?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The install type, either AGENT or GATEWAY
     */
    readonly installType?: string;
    /**
     * true, if the agent image is manually downloaded and installed. false, if the agent is deployed as a plugin in Oracle Cloud Agent.
     */
    readonly isCustomerDeployed?: boolean;
    /**
     * The list of management_agents.
     */
    readonly managementAgents: outputs.ManagementAgent.GetManagementAgentsManagementAgent[];
    /**
     * Platform Type
     */
    readonly platformTypes?: string[];
    /**
     * Management Agent Plugin Name
     */
    readonly pluginNames?: string[];
    /**
     * The current state of managementAgent
     */
    readonly state?: string;
    /**
     * Management Agent Version
     */
    readonly versions?: string[];
    readonly waitForHostId?: number;
}
/**
 * This data source provides the list of Management Agents in Oracle Cloud Infrastructure Management Agent service.
 *
 * Returns a list of Management Agents.
 * If no explicit page size limit is specified, it will default to 1000 when compartmentIdInSubtree is true and 5000 otherwise.
 * The response is limited to maximum 1000 records when compartmentIdInSubtree is true.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagementAgents = oci.ManagementAgent.getManagementAgents({
 *     compartmentId: compartmentId,
 *     accessLevel: managementAgentAccessLevel,
 *     availabilityStatus: managementAgentAvailabilityStatus,
 *     compartmentIdInSubtree: managementAgentCompartmentIdInSubtree,
 *     dataSourceNames: testManagementAgentDataSource.name,
 *     dataSourceType: managementAgentDataSourceType,
 *     displayName: managementAgentDisplayName,
 *     gatewayIds: testGateway.id,
 *     hostId: testHost.id,
 *     waitForHostId: 10,
 *     installType: managementAgentInstallType,
 *     isCustomerDeployed: managementAgentIsCustomerDeployed,
 *     platformTypes: managementAgentPlatformType,
 *     pluginNames: managementAgentPluginName,
 *     state: managementAgentState,
 *     versions: managementAgentVersion,
 * });
 * ```
 */
export function getManagementAgentsOutput(args: GetManagementAgentsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagementAgentsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ManagementAgent/getManagementAgents:getManagementAgents", {
        "accessLevel": args.accessLevel,
        "availabilityStatus": args.availabilityStatus,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "dataSourceNames": args.dataSourceNames,
        "dataSourceType": args.dataSourceType,
        "displayName": args.displayName,
        "filters": args.filters,
        "gatewayIds": args.gatewayIds,
        "hostId": args.hostId,
        "installType": args.installType,
        "isCustomerDeployed": args.isCustomerDeployed,
        "platformTypes": args.platformTypes,
        "pluginNames": args.pluginNames,
        "state": args.state,
        "versions": args.versions,
        "waitForHostId": args.waitForHostId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagementAgents.
 */
export interface GetManagementAgentsOutputArgs {
    /**
     * When the value is "ACCESSIBLE", insufficient permissions for a compartment will filter out resources in that compartment without rejecting the request.
     */
    accessLevel?: pulumi.Input<string>;
    /**
     * Filter to return only Management Agents in the particular availability status.
     */
    availabilityStatus?: pulumi.Input<string>;
    /**
     * The OCID of the compartment to which a request will be scoped.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * if set to true then it fetches resources for all compartments where user has access to else only on the compartment specified.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    /**
     * Unique name of the dataSource.
     */
    dataSourceNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The type of the dataSource.
     */
    dataSourceType?: pulumi.Input<string>;
    /**
     * Filter to return only Management Agents having the particular display name.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.ManagementAgent.GetManagementAgentsFilterArgs>[]>;
    /**
     * Filter to return only results having the particular gatewayId.
     */
    gatewayIds?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Filter to return only Management Agents having the particular agent host id.
     */
    hostId?: pulumi.Input<string>;
    /**
     * A filter to return either agents or gateway types depending upon install type selected by user. By default both install type will be returned.
     */
    installType?: pulumi.Input<string>;
    /**
     * true, if the agent image is manually downloaded and installed. false, if the agent is deployed as a plugin in Oracle Cloud Agent.
     */
    isCustomerDeployed?: pulumi.Input<boolean>;
    /**
     * Array of PlatformTypes to return only results having the particular platform types. Example: ["LINUX"]
     */
    platformTypes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Array of pluginName to return only Management Agents having the particular Plugins installed. A special pluginName of 'None' can be provided and this will return only Management Agents having no plugin installed. Example: ["PluginA"]
     */
    pluginNames?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Filter to return only Management Agents in the particular lifecycle state.
     */
    state?: pulumi.Input<string>;
    /**
     * Array of versions to return only Management Agents having the particular agent versions. Example: ["202020.0101","210201.0513"]
     */
    versions?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * When hostId argument is set, the data source will wait for the given period of time (in minutes) for this hostId to become available. This can be used when compute instance with Management Agent has been recently created.
     */
    waitForHostId?: pulumi.Input<number>;
}
