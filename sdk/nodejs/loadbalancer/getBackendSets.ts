// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Backend Sets in Oracle Cloud Infrastructure Load Balancer service.
 *
 * Lists all backend sets associated with a given load balancer.
 *
 * ## Supported Aliases
 *
 * * `ociLoadBalancerBackendsets`
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBackendSets = oci.LoadBalancer.getBackendSets({
 *     loadBalancerId: oci_load_balancer_load_balancer.test_load_balancer.id,
 * });
 * ```
 */
export function getBackendSets(args: GetBackendSetsArgs, opts?: pulumi.InvokeOptions): Promise<GetBackendSetsResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:LoadBalancer/getBackendSets:getBackendSets", {
        "filters": args.filters,
        "loadBalancerId": args.loadBalancerId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBackendSets.
 */
export interface GetBackendSetsArgs {
    filters?: inputs.LoadBalancer.GetBackendSetsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend sets to retrieve.
     */
    loadBalancerId: string;
}

/**
 * A collection of values returned by getBackendSets.
 */
export interface GetBackendSetsResult {
    /**
     * The list of backendsets.
     */
    readonly backendsets: outputs.LoadBalancer.GetBackendSetsBackendset[];
    readonly filters?: outputs.LoadBalancer.GetBackendSetsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly loadBalancerId: string;
}

export function getBackendSetsOutput(args: GetBackendSetsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetBackendSetsResult> {
    return pulumi.output(args).apply(a => getBackendSets(a, opts))
}

/**
 * A collection of arguments for invoking getBackendSets.
 */
export interface GetBackendSetsOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.LoadBalancer.GetBackendSetsFilterArgs>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend sets to retrieve.
     */
    loadBalancerId: pulumi.Input<string>;
}