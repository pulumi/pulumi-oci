// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Awr Hubs in Oracle Cloud Infrastructure Opsi service.
 *
 * Gets a list of AWR hubs. Either compartmentId or id must be specified. All these resources are expected to be in root compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAwrHubs = oci.Opsi.getAwrHubs({
 *     operationsInsightsWarehouseId: oci_opsi_operations_insights_warehouse.test_operations_insights_warehouse.id,
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.awr_hub_display_name,
 *     id: _var.awr_hub_id,
 *     states: _var.awr_hub_state,
 * });
 * ```
 */
export function getAwrHubs(args: GetAwrHubsArgs, opts?: pulumi.InvokeOptions): Promise<GetAwrHubsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Opsi/getAwrHubs:getAwrHubs", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "operationsInsightsWarehouseId": args.operationsInsightsWarehouseId,
        "states": args.states,
    }, opts);
}

/**
 * A collection of arguments for invoking getAwrHubs.
 */
export interface GetAwrHubsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: string;
    /**
     * A filter to return only resources that match the entire display name.
     */
    displayName?: string;
    filters?: inputs.Opsi.GetAwrHubsFilter[];
    /**
     * Unique Awr Hub identifier
     */
    id?: string;
    /**
     * Unique Operations Insights Warehouse identifier
     */
    operationsInsightsWarehouseId: string;
    /**
     * Lifecycle states
     */
    states?: string[];
}

/**
 * A collection of values returned by getAwrHubs.
 */
export interface GetAwrHubsResult {
    /**
     * The list of awr_hub_summary_collection.
     */
    readonly awrHubSummaryCollections: outputs.Opsi.GetAwrHubsAwrHubSummaryCollection[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId?: string;
    /**
     * User-friedly name of AWR Hub that does not have to be unique.
     */
    readonly displayName?: string;
    readonly filters?: outputs.Opsi.GetAwrHubsFilter[];
    /**
     * AWR Hub OCID
     */
    readonly id?: string;
    /**
     * OPSI Warehouse OCID
     */
    readonly operationsInsightsWarehouseId: string;
    /**
     * Possible lifecycle states
     */
    readonly states?: string[];
}

export function getAwrHubsOutput(args: GetAwrHubsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetAwrHubsResult> {
    return pulumi.output(args).apply(a => getAwrHubs(a, opts))
}

/**
 * A collection of arguments for invoking getAwrHubs.
 */
export interface GetAwrHubsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Opsi.GetAwrHubsFilterArgs>[]>;
    /**
     * Unique Awr Hub identifier
     */
    id?: pulumi.Input<string>;
    /**
     * Unique Operations Insights Warehouse identifier
     */
    operationsInsightsWarehouseId: pulumi.Input<string>;
    /**
     * Lifecycle states
     */
    states?: pulumi.Input<pulumi.Input<string>[]>;
}