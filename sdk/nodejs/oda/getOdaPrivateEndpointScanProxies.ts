// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Oda Private Endpoint Scan Proxies in Oracle Cloud Infrastructure Digital Assistant service.
 *
 * Returns a page of ODA Private Endpoint Scan Proxies that belong to the specified
 * ODA Private Endpoint.
 *
 * If the `opc-next-page` header appears in the response, then
 * there are more items to retrieve. To get the next page in the subsequent
 * GET request, include the header's value as the `page` query parameter.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOdaPrivateEndpointScanProxies = oci.Oda.getOdaPrivateEndpointScanProxies({
 *     odaPrivateEndpointId: oci_oda_oda_private_endpoint.test_oda_private_endpoint.id,
 *     state: _var.oda_private_endpoint_scan_proxy_state,
 * });
 * ```
 */
export function getOdaPrivateEndpointScanProxies(args: GetOdaPrivateEndpointScanProxiesArgs, opts?: pulumi.InvokeOptions): Promise<GetOdaPrivateEndpointScanProxiesResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Oda/getOdaPrivateEndpointScanProxies:getOdaPrivateEndpointScanProxies", {
        "filters": args.filters,
        "odaPrivateEndpointId": args.odaPrivateEndpointId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getOdaPrivateEndpointScanProxies.
 */
export interface GetOdaPrivateEndpointScanProxiesArgs {
    filters?: inputs.Oda.GetOdaPrivateEndpointScanProxiesFilter[];
    /**
     * Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    odaPrivateEndpointId: string;
    /**
     * List only the ODA Private Endpoint Scan Proxies that are in this lifecycle state.
     */
    state?: string;
}

/**
 * A collection of values returned by getOdaPrivateEndpointScanProxies.
 */
export interface GetOdaPrivateEndpointScanProxiesResult {
    readonly filters?: outputs.Oda.GetOdaPrivateEndpointScanProxiesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly odaPrivateEndpointId: string;
    /**
     * The list of oda_private_endpoint_scan_proxy_collection.
     */
    readonly odaPrivateEndpointScanProxyCollections: outputs.Oda.GetOdaPrivateEndpointScanProxiesOdaPrivateEndpointScanProxyCollection[];
    /**
     * The current state of the ODA Private Endpoint Scan Proxy.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Oda Private Endpoint Scan Proxies in Oracle Cloud Infrastructure Digital Assistant service.
 *
 * Returns a page of ODA Private Endpoint Scan Proxies that belong to the specified
 * ODA Private Endpoint.
 *
 * If the `opc-next-page` header appears in the response, then
 * there are more items to retrieve. To get the next page in the subsequent
 * GET request, include the header's value as the `page` query parameter.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOdaPrivateEndpointScanProxies = oci.Oda.getOdaPrivateEndpointScanProxies({
 *     odaPrivateEndpointId: oci_oda_oda_private_endpoint.test_oda_private_endpoint.id,
 *     state: _var.oda_private_endpoint_scan_proxy_state,
 * });
 * ```
 */
export function getOdaPrivateEndpointScanProxiesOutput(args: GetOdaPrivateEndpointScanProxiesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetOdaPrivateEndpointScanProxiesResult> {
    return pulumi.output(args).apply((a: any) => getOdaPrivateEndpointScanProxies(a, opts))
}

/**
 * A collection of arguments for invoking getOdaPrivateEndpointScanProxies.
 */
export interface GetOdaPrivateEndpointScanProxiesOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.Oda.GetOdaPrivateEndpointScanProxiesFilterArgs>[]>;
    /**
     * Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    odaPrivateEndpointId: pulumi.Input<string>;
    /**
     * List only the ODA Private Endpoint Scan Proxies that are in this lifecycle state.
     */
    state?: pulumi.Input<string>;
}