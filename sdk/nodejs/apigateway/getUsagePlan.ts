// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Usage Plan resource in Oracle Cloud Infrastructure API Gateway service.
 *
 * Gets a usage plan by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testUsagePlan = oci.ApiGateway.getUsagePlan({
 *     usagePlanId: testUsagePlanOciApigatewayUsagePlan.id,
 * });
 * ```
 */
export function getUsagePlan(args: GetUsagePlanArgs, opts?: pulumi.InvokeOptions): Promise<GetUsagePlanResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ApiGateway/getUsagePlan:getUsagePlan", {
        "usagePlanId": args.usagePlanId,
    }, opts);
}

/**
 * A collection of arguments for invoking getUsagePlan.
 */
export interface GetUsagePlanArgs {
    /**
     * The ocid of the usage plan.
     */
    usagePlanId: string;
}

/**
 * A collection of values returned by getUsagePlan.
 */
export interface GetUsagePlanResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    readonly displayName: string;
    /**
     * A collection of entitlements currently assigned to the usage plan.
     */
    readonly entitlements: outputs.ApiGateway.GetUsagePlanEntitlement[];
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a usage plan resource.
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * The current state of the usage plan.
     */
    readonly state: string;
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
    readonly usagePlanId: string;
}
/**
 * This data source provides details about a specific Usage Plan resource in Oracle Cloud Infrastructure API Gateway service.
 *
 * Gets a usage plan by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testUsagePlan = oci.ApiGateway.getUsagePlan({
 *     usagePlanId: testUsagePlanOciApigatewayUsagePlan.id,
 * });
 * ```
 */
export function getUsagePlanOutput(args: GetUsagePlanOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetUsagePlanResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ApiGateway/getUsagePlan:getUsagePlan", {
        "usagePlanId": args.usagePlanId,
    }, opts);
}

/**
 * A collection of arguments for invoking getUsagePlan.
 */
export interface GetUsagePlanOutputArgs {
    /**
     * The ocid of the usage plan.
     */
    usagePlanId: pulumi.Input<string>;
}
