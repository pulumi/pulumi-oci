// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Host Insights in Oracle Cloud Infrastructure Opsi service.
 *
 * Gets a list of host insights based on the query parameters specified. Either compartmentId or id query parameter must be specified.
 * When both compartmentId and compartmentIdInSubtree are specified, a list of host insights in that compartment and in all sub-compartments will be returned.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testHostInsights = oci.Opsi.getHostInsights({
 *     compartmentId: _var.compartment_id,
 *     compartmentIdInSubtree: _var.host_insight_compartment_id_in_subtree,
 *     enterpriseManagerBridgeId: oci_opsi_enterprise_manager_bridge.test_enterprise_manager_bridge.id,
 *     exadataInsightId: oci_opsi_exadata_insight.test_exadata_insight.id,
 *     hostTypes: _var.host_insight_host_type,
 *     id: _var.host_insight_id,
 *     states: _var.host_insight_state,
 *     statuses: _var.host_insight_status,
 * });
 * ```
 */
export function getHostInsights(args?: GetHostInsightsArgs, opts?: pulumi.InvokeOptions): Promise<GetHostInsightsResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Opsi/getHostInsights:getHostInsights", {
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "enterpriseManagerBridgeId": args.enterpriseManagerBridgeId,
        "exadataInsightId": args.exadataInsightId,
        "filters": args.filters,
        "hostTypes": args.hostTypes,
        "id": args.id,
        "states": args.states,
        "statuses": args.statuses,
    }, opts);
}

/**
 * A collection of arguments for invoking getHostInsights.
 */
export interface GetHostInsightsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: string;
    /**
     * A flag to search all resources within a given compartment and all sub-compartments.
     */
    compartmentIdInSubtree?: boolean;
    /**
     * Unique Enterprise Manager bridge identifier
     */
    enterpriseManagerBridgeId?: string;
    /**
     * [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of exadata insight resource.
     */
    exadataInsightId?: string;
    filters?: inputs.Opsi.GetHostInsightsFilter[];
    /**
     * Filter by one or more host types. Possible value is EXTERNAL-HOST.
     */
    hostTypes?: string[];
    /**
     * Optional list of host insight resource [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    id?: string;
    /**
     * Lifecycle states
     */
    states?: string[];
    /**
     * Resource Status
     */
    statuses?: string[];
}

/**
 * A collection of values returned by getHostInsights.
 */
export interface GetHostInsightsResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId?: string;
    readonly compartmentIdInSubtree?: boolean;
    /**
     * OPSI Enterprise Manager Bridge OCID
     */
    readonly enterpriseManagerBridgeId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata insight.
     */
    readonly exadataInsightId?: string;
    readonly filters?: outputs.Opsi.GetHostInsightsFilter[];
    /**
     * The list of host_insight_summary_collection.
     */
    readonly hostInsightSummaryCollections: outputs.Opsi.GetHostInsightsHostInsightSummaryCollection[];
    /**
     * Operations Insights internal representation of the host type. Possible value is EXTERNAL-HOST.
     */
    readonly hostTypes?: string[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the host insight resource.
     */
    readonly id?: string;
    /**
     * The current state of the host.
     */
    readonly states?: string[];
    /**
     * Indicates the status of a host insight in Operations Insights
     */
    readonly statuses?: string[];
}

export function getHostInsightsOutput(args?: GetHostInsightsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetHostInsightsResult> {
    return pulumi.output(args).apply(a => getHostInsights(a, opts))
}

/**
 * A collection of arguments for invoking getHostInsights.
 */
export interface GetHostInsightsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * A flag to search all resources within a given compartment and all sub-compartments.
     */
    compartmentIdInSubtree?: pulumi.Input<boolean>;
    /**
     * Unique Enterprise Manager bridge identifier
     */
    enterpriseManagerBridgeId?: pulumi.Input<string>;
    /**
     * [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of exadata insight resource.
     */
    exadataInsightId?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Opsi.GetHostInsightsFilterArgs>[]>;
    /**
     * Filter by one or more host types. Possible value is EXTERNAL-HOST.
     */
    hostTypes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Optional list of host insight resource [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    id?: pulumi.Input<string>;
    /**
     * Lifecycle states
     */
    states?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Resource Status
     */
    statuses?: pulumi.Input<pulumi.Input<string>[]>;
}
