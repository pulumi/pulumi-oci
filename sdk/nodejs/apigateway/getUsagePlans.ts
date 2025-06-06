// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Usage Plans in Oracle Cloud Infrastructure API Gateway service.
 *
 * Returns a list of usage plans.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testUsagePlans = oci.ApiGateway.getUsagePlans({
 *     compartmentId: compartmentId,
 *     displayName: usagePlanDisplayName,
 *     state: usagePlanState,
 * });
 * ```
 */
export function getUsagePlans(args: GetUsagePlansArgs, opts?: pulumi.InvokeOptions): Promise<GetUsagePlansResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ApiGateway/getUsagePlans:getUsagePlans", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getUsagePlans.
 */
export interface GetUsagePlansArgs {
    /**
     * The ocid of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
     */
    displayName?: string;
    filters?: inputs.ApiGateway.GetUsagePlansFilter[];
    /**
     * A filter to return only resources that match the given lifecycle state. Example: `ACTIVE`
     */
    state?: string;
}

/**
 * A collection of values returned by getUsagePlans.
 */
export interface GetUsagePlansResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     */
    readonly compartmentId: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    readonly displayName?: string;
    readonly filters?: outputs.ApiGateway.GetUsagePlansFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the usage plan.
     */
    readonly state?: string;
    /**
     * The list of usage_plan_collection.
     */
    readonly usagePlanCollections: outputs.ApiGateway.GetUsagePlansUsagePlanCollection[];
}
/**
 * This data source provides the list of Usage Plans in Oracle Cloud Infrastructure API Gateway service.
 *
 * Returns a list of usage plans.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testUsagePlans = oci.ApiGateway.getUsagePlans({
 *     compartmentId: compartmentId,
 *     displayName: usagePlanDisplayName,
 *     state: usagePlanState,
 * });
 * ```
 */
export function getUsagePlansOutput(args: GetUsagePlansOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetUsagePlansResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ApiGateway/getUsagePlans:getUsagePlans", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getUsagePlans.
 */
export interface GetUsagePlansOutputArgs {
    /**
     * The ocid of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.ApiGateway.GetUsagePlansFilterArgs>[]>;
    /**
     * A filter to return only resources that match the given lifecycle state. Example: `ACTIVE`
     */
    state?: pulumi.Input<string>;
}
