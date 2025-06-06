// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Endpoints in Oracle Cloud Infrastructure Generative AI service.
 *
 * Lists the endpoints of a specific compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testEndpoints = oci.GenerativeAi.getEndpoints({
 *     compartmentId: compartmentId,
 *     displayName: endpointDisplayName,
 *     id: endpointId,
 *     state: endpointState,
 * });
 * ```
 */
export function getEndpoints(args: GetEndpointsArgs, opts?: pulumi.InvokeOptions): Promise<GetEndpointsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:GenerativeAi/getEndpoints:getEndpoints", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getEndpoints.
 */
export interface GetEndpointsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.GenerativeAi.GetEndpointsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the endpoint.
     */
    id?: string;
    /**
     * A filter to return only resources that their lifecycle state matches the given lifecycle state.
     */
    state?: string;
}

/**
 * A collection of values returned by getEndpoints.
 */
export interface GetEndpointsResult {
    readonly compartmentId: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable.
     */
    readonly displayName?: string;
    /**
     * The list of endpoint_collection.
     */
    readonly endpointCollections: outputs.GenerativeAi.GetEndpointsEndpointCollection[];
    readonly filters?: outputs.GenerativeAi.GetEndpointsFilter[];
    readonly id?: string;
    /**
     * The current state of the endpoint.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Endpoints in Oracle Cloud Infrastructure Generative AI service.
 *
 * Lists the endpoints of a specific compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testEndpoints = oci.GenerativeAi.getEndpoints({
 *     compartmentId: compartmentId,
 *     displayName: endpointDisplayName,
 *     id: endpointId,
 *     state: endpointState,
 * });
 * ```
 */
export function getEndpointsOutput(args: GetEndpointsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetEndpointsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:GenerativeAi/getEndpoints:getEndpoints", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getEndpoints.
 */
export interface GetEndpointsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.GenerativeAi.GetEndpointsFilterArgs>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the endpoint.
     */
    id?: pulumi.Input<string>;
    /**
     * A filter to return only resources that their lifecycle state matches the given lifecycle state.
     */
    state?: pulumi.Input<string>;
}
