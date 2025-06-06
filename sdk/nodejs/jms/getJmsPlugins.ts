// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Jms Plugins in Oracle Cloud Infrastructure Jms service.
 *
 * Lists the JmsPlugins.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testJmsPlugins = oci.Jms.getJmsPlugins({
 *     agentId: jmsPluginAgentId,
 *     agentType: jmsPluginAgentType,
 *     availabilityStatus: jmsPluginAvailabilityStatus,
 *     compartmentId: compartmentId,
 *     compartmentIdInSubtree: jmsPluginCompartmentIdInSubtree,
 *     fleetId: testFleet.id,
 *     hostnameContains: jmsPluginHostnameContains,
 *     id: jmsPluginId,
 *     state: jmsPluginState,
 *     timeLastSeenLessThanOrEqualTo: jmsPluginTimeLastSeenLessThanOrEqualTo,
 *     timeRegisteredLessThanOrEqualTo: jmsPluginTimeRegisteredLessThanOrEqualTo,
 * });
 * ```
 */
export function getJmsPlugins(args?: GetJmsPluginsArgs, opts?: pulumi.InvokeOptions): Promise<GetJmsPluginsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Jms/getJmsPlugins:getJmsPlugins", {
        "agentId": args.agentId,
        "agentType": args.agentType,
        "availabilityStatus": args.availabilityStatus,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "filters": args.filters,
        "fleetId": args.fleetId,
        "hostnameContains": args.hostnameContains,
        "id": args.id,
        "state": args.state,
        "timeLastSeenLessThanOrEqualTo": args.timeLastSeenLessThanOrEqualTo,
        "timeRegisteredLessThanOrEqualTo": args.timeRegisteredLessThanOrEqualTo,
    }, opts);
}

/**
 * A collection of arguments for invoking getJmsPlugins.
 */
export interface GetJmsPluginsArgs {
    /**
     * The ManagementAgent (OMA) or Instance (OCA) [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) that identifies the Agent.
     */
    agentId?: string;
    /**
     * Filter JmsPlugin with agent type.
     */
    agentType?: string;
    /**
     * Filter JmsPlugin with its availability status.
     */
    availabilityStatus?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     */
    compartmentId?: string;
    /**
     * Flag to determine whether the info should be gathered only in the compartment or in the compartment and its subcompartments.
     */
    compartmentIdInSubtree?: boolean;
    filters?: inputs.Jms.GetJmsPluginsFilter[];
    /**
     * The ID of the Fleet.
     */
    fleetId?: string;
    /**
     * Filter the list with hostname contains the given value.
     */
    hostnameContains?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the JmsPlugin.
     */
    id?: string;
    /**
     * Filter JmsPlugin with its lifecycle state.
     */
    state?: string;
    /**
     * If present, only plugins with a last seen time before this parameter are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     */
    timeLastSeenLessThanOrEqualTo?: string;
    /**
     * If present, only plugins with a registration time before this parameter are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     */
    timeRegisteredLessThanOrEqualTo?: string;
}

/**
 * A collection of values returned by getJmsPlugins.
 */
export interface GetJmsPluginsResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Management Agent (OMA) or the Oracle Cloud Agent (OCA) instance where the JMS plugin is deployed.
     */
    readonly agentId?: string;
    /**
     * The agent type.
     */
    readonly agentType?: string;
    /**
     * The availability status.
     */
    readonly availabilityStatus?: string;
    /**
     * The OMA/OCA agent's compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    readonly compartmentId?: string;
    readonly compartmentIdInSubtree?: boolean;
    readonly filters?: outputs.Jms.GetJmsPluginsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet.
     */
    readonly fleetId?: string;
    readonly hostnameContains?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to identify this JmsPlugin.
     */
    readonly id?: string;
    /**
     * The list of jms_plugin_collection.
     */
    readonly jmsPluginCollections: outputs.Jms.GetJmsPluginsJmsPluginCollection[];
    /**
     * The lifecycle state.
     */
    readonly state?: string;
    readonly timeLastSeenLessThanOrEqualTo?: string;
    readonly timeRegisteredLessThanOrEqualTo?: string;
}
/**
 * This data source provides the list of Jms Plugins in Oracle Cloud Infrastructure Jms service.
 *
 * Lists the JmsPlugins.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testJmsPlugins = oci.Jms.getJmsPlugins({
 *     agentId: jmsPluginAgentId,
 *     agentType: jmsPluginAgentType,
 *     availabilityStatus: jmsPluginAvailabilityStatus,
 *     compartmentId: compartmentId,
 *     compartmentIdInSubtree: jmsPluginCompartmentIdInSubtree,
 *     fleetId: testFleet.id,
 *     hostnameContains: jmsPluginHostnameContains,
 *     id: jmsPluginId,
 *     state: jmsPluginState,
 *     timeLastSeenLessThanOrEqualTo: jmsPluginTimeLastSeenLessThanOrEqualTo,
 *     timeRegisteredLessThanOrEqualTo: jmsPluginTimeRegisteredLessThanOrEqualTo,
 * });
 * ```
 */
export function getJmsPluginsOutput(args?: GetJmsPluginsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetJmsPluginsResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Jms/getJmsPlugins:getJmsPlugins", {
        "agentId": args.agentId,
        "agentType": args.agentType,
        "availabilityStatus": args.availabilityStatus,
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "filters": args.filters,
        "fleetId": args.fleetId,
        "hostnameContains": args.hostnameContains,
        "id": args.id,
        "state": args.state,
        "timeLastSeenLessThanOrEqualTo": args.timeLastSeenLessThanOrEqualTo,
        "timeRegisteredLessThanOrEqualTo": args.timeRegisteredLessThanOrEqualTo,
    }, opts);
}

/**
 * A collection of arguments for invoking getJmsPlugins.
 */
export interface GetJmsPluginsOutputArgs {
    /**
     * The ManagementAgent (OMA) or Instance (OCA) [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) that identifies the Agent.
     */
    agentId?: pulumi.Input<string>;
    /**
     * Filter JmsPlugin with agent type.
     */
    agentType?: pulumi.Input<string>;
    /**
     * Filter JmsPlugin with its availability status.
     */
    availabilityStatus?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Flag to determine whether the info should be gathered only in the compartment or in the compartment and its subcompartments.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    filters?: pulumi.Input<pulumi.Input<inputs.Jms.GetJmsPluginsFilterArgs>[]>;
    /**
     * The ID of the Fleet.
     */
    fleetId?: pulumi.Input<string>;
    /**
     * Filter the list with hostname contains the given value.
     */
    hostnameContains?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the JmsPlugin.
     */
    id?: pulumi.Input<string>;
    /**
     * Filter JmsPlugin with its lifecycle state.
     */
    state?: pulumi.Input<string>;
    /**
     * If present, only plugins with a last seen time before this parameter are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     */
    timeLastSeenLessThanOrEqualTo?: pulumi.Input<string>;
    /**
     * If present, only plugins with a registration time before this parameter are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     */
    timeRegisteredLessThanOrEqualTo?: pulumi.Input<string>;
}
