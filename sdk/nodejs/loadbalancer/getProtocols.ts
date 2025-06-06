// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Load Balancer Protocols in Oracle Cloud Infrastructure Load Balancer service.
 *
 * Lists all supported traffic protocols.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testLoadBalancerProtocols = oci.LoadBalancer.getProtocols({
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getProtocols(args: GetProtocolsArgs, opts?: pulumi.InvokeOptions): Promise<GetProtocolsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:LoadBalancer/getProtocols:getProtocols", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getProtocols.
 */
export interface GetProtocolsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the load balancer protocols to list.
     */
    compartmentId: string;
    filters?: inputs.LoadBalancer.GetProtocolsFilter[];
}

/**
 * A collection of values returned by getProtocols.
 */
export interface GetProtocolsResult {
    readonly compartmentId: string;
    readonly filters?: outputs.LoadBalancer.GetProtocolsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of protocols.
     */
    readonly protocols: outputs.LoadBalancer.GetProtocolsProtocol[];
}
/**
 * This data source provides the list of Load Balancer Protocols in Oracle Cloud Infrastructure Load Balancer service.
 *
 * Lists all supported traffic protocols.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testLoadBalancerProtocols = oci.LoadBalancer.getProtocols({
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getProtocolsOutput(args: GetProtocolsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetProtocolsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:LoadBalancer/getProtocols:getProtocols", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getProtocols.
 */
export interface GetProtocolsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the load balancer protocols to list.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.LoadBalancer.GetProtocolsFilterArgs>[]>;
}
