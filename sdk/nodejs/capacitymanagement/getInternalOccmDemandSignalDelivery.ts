// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Internal Occm Demand Signal Delivery resource in Oracle Cloud Infrastructure Capacity Management service.
 *
 * This is an internal GET API to get the details of a demand signal delivery resource corresponding to a demand signal item.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInternalOccmDemandSignalDelivery = oci.CapacityManagement.getInternalOccmDemandSignalDelivery({
 *     occmDemandSignalDeliveryId: testOccmDemandSignalDelivery.id,
 * });
 * ```
 */
export function getInternalOccmDemandSignalDelivery(args: GetInternalOccmDemandSignalDeliveryArgs, opts?: pulumi.InvokeOptions): Promise<GetInternalOccmDemandSignalDeliveryResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:CapacityManagement/getInternalOccmDemandSignalDelivery:getInternalOccmDemandSignalDelivery", {
        "occmDemandSignalDeliveryId": args.occmDemandSignalDeliveryId,
    }, opts);
}

/**
 * A collection of arguments for invoking getInternalOccmDemandSignalDelivery.
 */
export interface GetInternalOccmDemandSignalDeliveryArgs {
    /**
     * The OCID of the demand signal delivery.
     */
    occmDemandSignalDeliveryId: string;
}

/**
 * A collection of values returned by getInternalOccmDemandSignalDelivery.
 */
export interface GetInternalOccmDemandSignalDeliveryResult {
    /**
     * The quantity of the resource that Oracle Cloud Infrastructure will supply to the customer.
     */
    readonly acceptedQuantity: string;
    /**
     * The OCID of the tenancy from which the demand signal delivery resource is created.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * The OCID of the demand signal under which this delivery will be grouped.
     */
    readonly demandSignalId: string;
    /**
     * The OCID of the demand signal item corresponding to which this delivery is made.
     */
    readonly demandSignalItemId: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The OCID of this demand signal delivery resource.
     */
    readonly id: string;
    /**
     * This field could be used by Oracle Cloud Infrastructure to communicate the reason for accepting or declining the request.
     */
    readonly justification: string;
    /**
     * The enum values corresponding to the various states associated with the delivery resource.
     */
    readonly lifecycleDetails: string;
    /**
     * This field acts as a notes section for operators.
     */
    readonly notes: string;
    /**
     * The OCID of the corresponding customer group to which this demand signal delivery resource belongs to.
     */
    readonly occCustomerGroupId: string;
    readonly occmDemandSignalDeliveryId: string;
    /**
     * The current lifecycle state of the resource.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The date on which the Oracle Cloud Infrastructure delivered the resource to the customers. The default value for this will be the corresponding demand signal item resource's need by date.
     */
    readonly timeDelivered: string;
}
/**
 * This data source provides details about a specific Internal Occm Demand Signal Delivery resource in Oracle Cloud Infrastructure Capacity Management service.
 *
 * This is an internal GET API to get the details of a demand signal delivery resource corresponding to a demand signal item.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInternalOccmDemandSignalDelivery = oci.CapacityManagement.getInternalOccmDemandSignalDelivery({
 *     occmDemandSignalDeliveryId: testOccmDemandSignalDelivery.id,
 * });
 * ```
 */
export function getInternalOccmDemandSignalDeliveryOutput(args: GetInternalOccmDemandSignalDeliveryOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetInternalOccmDemandSignalDeliveryResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:CapacityManagement/getInternalOccmDemandSignalDelivery:getInternalOccmDemandSignalDelivery", {
        "occmDemandSignalDeliveryId": args.occmDemandSignalDeliveryId,
    }, opts);
}

/**
 * A collection of arguments for invoking getInternalOccmDemandSignalDelivery.
 */
export interface GetInternalOccmDemandSignalDeliveryOutputArgs {
    /**
     * The OCID of the demand signal delivery.
     */
    occmDemandSignalDeliveryId: pulumi.Input<string>;
}
