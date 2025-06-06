// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Occ Customer Group resource in Oracle Cloud Infrastructure Capacity Management service.
 *
 * Gets information about the specified customer group.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOccCustomerGroup = oci.CapacityManagement.getOccCustomerGroup({
 *     occCustomerGroupId: testOccCustomerGroupOciCapacityManagementOccCustomerGroup.id,
 * });
 * ```
 */
export function getOccCustomerGroup(args: GetOccCustomerGroupArgs, opts?: pulumi.InvokeOptions): Promise<GetOccCustomerGroupResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:CapacityManagement/getOccCustomerGroup:getOccCustomerGroup", {
        "occCustomerGroupId": args.occCustomerGroupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getOccCustomerGroup.
 */
export interface GetOccCustomerGroupArgs {
    /**
     * The OCID of the customer group.
     */
    occCustomerGroupId: string;
}

/**
 * A collection of values returned by getOccCustomerGroup.
 */
export interface GetOccCustomerGroupResult {
    /**
     * The OCID of the tenancy containing the customer group.
     */
    readonly compartmentId: string;
    /**
     * A list containing all the customers that belong to this customer group
     */
    readonly customersLists: outputs.CapacityManagement.GetOccCustomerGroupCustomersList[];
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * The description about the customer group.
     */
    readonly description: string;
    /**
     * The display name of the customer group.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The OCID of the customer group.
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed State.
     */
    readonly lifecycleDetails: string;
    /**
     * The OCID of the customer group.
     */
    readonly occCustomerGroupId: string;
    /**
     * The current lifecycle state of the resource.
     */
    readonly state: string;
    /**
     * To determine whether the customer group is enabled/disabled.
     */
    readonly status: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The time when the customer group was created.
     */
    readonly timeCreated: string;
    /**
     * The time when the customer group was last updated.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Occ Customer Group resource in Oracle Cloud Infrastructure Capacity Management service.
 *
 * Gets information about the specified customer group.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOccCustomerGroup = oci.CapacityManagement.getOccCustomerGroup({
 *     occCustomerGroupId: testOccCustomerGroupOciCapacityManagementOccCustomerGroup.id,
 * });
 * ```
 */
export function getOccCustomerGroupOutput(args: GetOccCustomerGroupOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetOccCustomerGroupResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:CapacityManagement/getOccCustomerGroup:getOccCustomerGroup", {
        "occCustomerGroupId": args.occCustomerGroupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getOccCustomerGroup.
 */
export interface GetOccCustomerGroupOutputArgs {
    /**
     * The OCID of the customer group.
     */
    occCustomerGroupId: pulumi.Input<string>;
}
