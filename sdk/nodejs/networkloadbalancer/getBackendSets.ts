// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Backend Sets in Oracle Cloud Infrastructure Network Load Balancer service.
 *
 * Lists all backend sets associated with a given network load balancer.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBackendSets = oci.NetworkLoadBalancer.getBackendSets({
 *     networkLoadBalancerId: testNetworkLoadBalancer.id,
 * });
 * ```
 */
export function getBackendSets(args: GetBackendSetsArgs, opts?: pulumi.InvokeOptions): Promise<GetBackendSetsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:NetworkLoadBalancer/getBackendSets:getBackendSets", {
        "filters": args.filters,
        "networkLoadBalancerId": args.networkLoadBalancerId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBackendSets.
 */
export interface GetBackendSetsArgs {
    filters?: inputs.NetworkLoadBalancer.GetBackendSetsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     */
    networkLoadBalancerId: string;
}

/**
 * A collection of values returned by getBackendSets.
 */
export interface GetBackendSetsResult {
    /**
     * The list of backend_set_collection.
     */
    readonly backendSetCollections: outputs.NetworkLoadBalancer.GetBackendSetsBackendSetCollection[];
    readonly filters?: outputs.NetworkLoadBalancer.GetBackendSetsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly networkLoadBalancerId: string;
}
/**
 * This data source provides the list of Backend Sets in Oracle Cloud Infrastructure Network Load Balancer service.
 *
 * Lists all backend sets associated with a given network load balancer.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBackendSets = oci.NetworkLoadBalancer.getBackendSets({
 *     networkLoadBalancerId: testNetworkLoadBalancer.id,
 * });
 * ```
 */
export function getBackendSetsOutput(args: GetBackendSetsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetBackendSetsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:NetworkLoadBalancer/getBackendSets:getBackendSets", {
        "filters": args.filters,
        "networkLoadBalancerId": args.networkLoadBalancerId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBackendSets.
 */
export interface GetBackendSetsOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.NetworkLoadBalancer.GetBackendSetsFilterArgs>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     */
    networkLoadBalancerId: pulumi.Input<string>;
}
