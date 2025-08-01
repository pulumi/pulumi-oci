// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Occm Demand Signal Deliveries in Oracle Cloud Infrastructure Capacity Management service.
 *
 * This GET call is used to list all demand signals delivery resources within the compartment passed as a query param.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOccmDemandSignalDeliveries = oci.CapacityManagement.getOccmDemandSignalDeliveries({
 *     compartmentId: compartmentId,
 *     id: occmDemandSignalDeliveryId,
 *     occmDemandSignalItemId: testOccmDemandSignalItem.id,
 * });
 * ```
 */
export function getOccmDemandSignalDeliveries(args: GetOccmDemandSignalDeliveriesArgs, opts?: pulumi.InvokeOptions): Promise<GetOccmDemandSignalDeliveriesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:CapacityManagement/getOccmDemandSignalDeliveries:getOccmDemandSignalDeliveries", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "id": args.id,
        "occmDemandSignalItemId": args.occmDemandSignalItemId,
    }, opts);
}

/**
 * A collection of arguments for invoking getOccmDemandSignalDeliveries.
 */
export interface GetOccmDemandSignalDeliveriesArgs {
    /**
     * The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
     */
    compartmentId: string;
    filters?: inputs.CapacityManagement.GetOccmDemandSignalDeliveriesFilter[];
    /**
     * A query parameter to filter the list of demand signals based on it's OCID.
     */
    id?: string;
    /**
     * A query parameter to filter the list of demand signal items based on it's OCID.
     */
    occmDemandSignalItemId?: string;
}

/**
 * A collection of values returned by getOccmDemandSignalDeliveries.
 */
export interface GetOccmDemandSignalDeliveriesResult {
    /**
     * The OCID of the tenancy from which the demand signal delivery resource is created.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.CapacityManagement.GetOccmDemandSignalDeliveriesFilter[];
    /**
     * The OCID of this demand signal delivery resource.
     */
    readonly id?: string;
    /**
     * The list of occm_demand_signal_delivery_collection.
     */
    readonly occmDemandSignalDeliveryCollections: outputs.CapacityManagement.GetOccmDemandSignalDeliveriesOccmDemandSignalDeliveryCollection[];
    readonly occmDemandSignalItemId?: string;
}
/**
 * This data source provides the list of Occm Demand Signal Deliveries in Oracle Cloud Infrastructure Capacity Management service.
 *
 * This GET call is used to list all demand signals delivery resources within the compartment passed as a query param.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOccmDemandSignalDeliveries = oci.CapacityManagement.getOccmDemandSignalDeliveries({
 *     compartmentId: compartmentId,
 *     id: occmDemandSignalDeliveryId,
 *     occmDemandSignalItemId: testOccmDemandSignalItem.id,
 * });
 * ```
 */
export function getOccmDemandSignalDeliveriesOutput(args: GetOccmDemandSignalDeliveriesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetOccmDemandSignalDeliveriesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:CapacityManagement/getOccmDemandSignalDeliveries:getOccmDemandSignalDeliveries", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "id": args.id,
        "occmDemandSignalItemId": args.occmDemandSignalItemId,
    }, opts);
}

/**
 * A collection of arguments for invoking getOccmDemandSignalDeliveries.
 */
export interface GetOccmDemandSignalDeliveriesOutputArgs {
    /**
     * The ocid of the compartment or tenancy in which resources are to be listed. This will also be used for authorization purposes.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.CapacityManagement.GetOccmDemandSignalDeliveriesFilterArgs>[]>;
    /**
     * A query parameter to filter the list of demand signals based on it's OCID.
     */
    id?: pulumi.Input<string>;
    /**
     * A query parameter to filter the list of demand signal items based on it's OCID.
     */
    occmDemandSignalItemId?: pulumi.Input<string>;
}
