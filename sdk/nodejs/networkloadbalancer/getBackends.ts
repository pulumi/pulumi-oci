// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Backends in Oracle Cloud Infrastructure Network Load Balancer service.
 *
 * Lists the backend servers for a given network load balancer and backend set.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBackends = oci.NetworkLoadBalancer.getBackends({
 *     backendSetName: testBackendSet.name,
 *     networkLoadBalancerId: testNetworkLoadBalancer.id,
 * });
 * ```
 */
export function getBackends(args: GetBackendsArgs, opts?: pulumi.InvokeOptions): Promise<GetBackendsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:NetworkLoadBalancer/getBackends:getBackends", {
        "backendSetName": args.backendSetName,
        "filters": args.filters,
        "networkLoadBalancerId": args.networkLoadBalancerId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBackends.
 */
export interface GetBackendsArgs {
    /**
     * The name of the backend set associated with the backend servers.  Example: `exampleBackendSet`
     */
    backendSetName: string;
    filters?: inputs.NetworkLoadBalancer.GetBackendsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     */
    networkLoadBalancerId: string;
}

/**
 * A collection of values returned by getBackends.
 */
export interface GetBackendsResult {
    /**
     * The list of backend_collection.
     */
    readonly backendCollections: outputs.NetworkLoadBalancer.GetBackendsBackendCollection[];
    readonly backendSetName: string;
    readonly filters?: outputs.NetworkLoadBalancer.GetBackendsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly networkLoadBalancerId: string;
}
/**
 * This data source provides the list of Backends in Oracle Cloud Infrastructure Network Load Balancer service.
 *
 * Lists the backend servers for a given network load balancer and backend set.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBackends = oci.NetworkLoadBalancer.getBackends({
 *     backendSetName: testBackendSet.name,
 *     networkLoadBalancerId: testNetworkLoadBalancer.id,
 * });
 * ```
 */
export function getBackendsOutput(args: GetBackendsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetBackendsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:NetworkLoadBalancer/getBackends:getBackends", {
        "backendSetName": args.backendSetName,
        "filters": args.filters,
        "networkLoadBalancerId": args.networkLoadBalancerId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBackends.
 */
export interface GetBackendsOutputArgs {
    /**
     * The name of the backend set associated with the backend servers.  Example: `exampleBackendSet`
     */
    backendSetName: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.NetworkLoadBalancer.GetBackendsFilterArgs>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     */
    networkLoadBalancerId: pulumi.Input<string>;
}
