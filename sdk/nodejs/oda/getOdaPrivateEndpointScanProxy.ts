// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Oda Private Endpoint Scan Proxy resource in Oracle Cloud Infrastructure Digital Assistant service.
 *
 * Gets the specified ODA Private Endpoint Scan Proxy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOdaPrivateEndpointScanProxy = oci.Oda.getOdaPrivateEndpointScanProxy({
 *     odaPrivateEndpointId: oci_oda_oda_private_endpoint.test_oda_private_endpoint.id,
 *     odaPrivateEndpointScanProxyId: oci_oda_oda_private_endpoint_scan_proxy.test_oda_private_endpoint_scan_proxy.id,
 * });
 * ```
 */
export function getOdaPrivateEndpointScanProxy(args: GetOdaPrivateEndpointScanProxyArgs, opts?: pulumi.InvokeOptions): Promise<GetOdaPrivateEndpointScanProxyResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Oda/getOdaPrivateEndpointScanProxy:getOdaPrivateEndpointScanProxy", {
        "odaPrivateEndpointId": args.odaPrivateEndpointId,
        "odaPrivateEndpointScanProxyId": args.odaPrivateEndpointScanProxyId,
    }, opts);
}

/**
 * A collection of arguments for invoking getOdaPrivateEndpointScanProxy.
 */
export interface GetOdaPrivateEndpointScanProxyArgs {
    /**
     * Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    odaPrivateEndpointId: string;
    /**
     * Unique ODA Private Endpoint Scan Proxy identifier.
     */
    odaPrivateEndpointScanProxyId: string;
}

/**
 * A collection of values returned by getOdaPrivateEndpointScanProxy.
 */
export interface GetOdaPrivateEndpointScanProxyResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ODA Private Endpoint Scan Proxy.
     */
    readonly id: string;
    readonly odaPrivateEndpointId: string;
    readonly odaPrivateEndpointScanProxyId: string;
    /**
     * The protocol used for communication between client, scanProxy and RAC's scan listeners
     */
    readonly protocol: string;
    /**
     * The FQDN/IPs and port information of customer's Real Application Cluster (RAC)'s SCAN listeners.
     */
    readonly scanListenerInfos: outputs.Oda.GetOdaPrivateEndpointScanProxyScanListenerInfo[];
    /**
     * Type indicating whether Scan listener is specified by its FQDN or list of IPs
     */
    readonly scanListenerType: string;
    /**
     * The current state of the ODA Private Endpoint Scan Proxy.
     */
    readonly state: string;
    /**
     * When the resource was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     */
    readonly timeCreated: string;
}
/**
 * This data source provides details about a specific Oda Private Endpoint Scan Proxy resource in Oracle Cloud Infrastructure Digital Assistant service.
 *
 * Gets the specified ODA Private Endpoint Scan Proxy.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOdaPrivateEndpointScanProxy = oci.Oda.getOdaPrivateEndpointScanProxy({
 *     odaPrivateEndpointId: oci_oda_oda_private_endpoint.test_oda_private_endpoint.id,
 *     odaPrivateEndpointScanProxyId: oci_oda_oda_private_endpoint_scan_proxy.test_oda_private_endpoint_scan_proxy.id,
 * });
 * ```
 */
export function getOdaPrivateEndpointScanProxyOutput(args: GetOdaPrivateEndpointScanProxyOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetOdaPrivateEndpointScanProxyResult> {
    return pulumi.output(args).apply((a: any) => getOdaPrivateEndpointScanProxy(a, opts))
}

/**
 * A collection of arguments for invoking getOdaPrivateEndpointScanProxy.
 */
export interface GetOdaPrivateEndpointScanProxyOutputArgs {
    /**
     * Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    odaPrivateEndpointId: pulumi.Input<string>;
    /**
     * Unique ODA Private Endpoint Scan Proxy identifier.
     */
    odaPrivateEndpointScanProxyId: pulumi.Input<string>;
}