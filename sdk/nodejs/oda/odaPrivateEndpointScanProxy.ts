// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Oda Private Endpoint Scan Proxy resource in Oracle Cloud Infrastructure Digital Assistant service.
 *
 * Starts an asynchronous job to create an ODA Private Endpoint Scan Proxy.
 *
 * To monitor the status of the job, take the `opc-work-request-id` response
 * header value and use it to call `GET /workRequests/{workRequestID}`.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOdaPrivateEndpointScanProxy = new oci.oda.OdaPrivateEndpointScanProxy("test_oda_private_endpoint_scan_proxy", {
 *     odaPrivateEndpointId: testOdaPrivateEndpoint.id,
 *     protocol: odaPrivateEndpointScanProxyProtocol,
 *     scanListenerInfos: [{
 *         scanListenerFqdn: odaPrivateEndpointScanProxyScanListenerInfosScanListenerFqdn,
 *         scanListenerIp: odaPrivateEndpointScanProxyScanListenerInfosScanListenerIp,
 *         scanListenerPort: odaPrivateEndpointScanProxyScanListenerInfosScanListenerPort,
 *     }],
 *     scanListenerType: odaPrivateEndpointScanProxyScanListenerType,
 * });
 * ```
 *
 * ## Import
 *
 * OdaPrivateEndpointScanProxies can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Oda/odaPrivateEndpointScanProxy:OdaPrivateEndpointScanProxy test_oda_private_endpoint_scan_proxy "odaPrivateEndpoints/{odaPrivateEndpointId}/odaPrivateEndpointScanProxies/{odaPrivateEndpointScanProxyId}"
 * ```
 */
export class OdaPrivateEndpointScanProxy extends pulumi.CustomResource {
    /**
     * Get an existing OdaPrivateEndpointScanProxy resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: OdaPrivateEndpointScanProxyState, opts?: pulumi.CustomResourceOptions): OdaPrivateEndpointScanProxy {
        return new OdaPrivateEndpointScanProxy(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Oda/odaPrivateEndpointScanProxy:OdaPrivateEndpointScanProxy';

    /**
     * Returns true if the given object is an instance of OdaPrivateEndpointScanProxy.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is OdaPrivateEndpointScanProxy {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === OdaPrivateEndpointScanProxy.__pulumiType;
    }

    /**
     * Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    public readonly odaPrivateEndpointId!: pulumi.Output<string>;
    /**
     * The protocol used for communication between client, scanProxy and RAC's scan listeners
     */
    public readonly protocol!: pulumi.Output<string>;
    /**
     * The FQDN/IPs and port information of customer's Real Application Cluster (RAC)'s SCAN listeners.
     */
    public readonly scanListenerInfos!: pulumi.Output<outputs.Oda.OdaPrivateEndpointScanProxyScanListenerInfo[]>;
    /**
     * Type indicating whether Scan listener is specified by its FQDN or list of IPs 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly scanListenerType!: pulumi.Output<string>;
    /**
     * The current state of the ODA Private Endpoint Scan Proxy.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * When the resource was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a OdaPrivateEndpointScanProxy resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: OdaPrivateEndpointScanProxyArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: OdaPrivateEndpointScanProxyArgs | OdaPrivateEndpointScanProxyState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as OdaPrivateEndpointScanProxyState | undefined;
            resourceInputs["odaPrivateEndpointId"] = state ? state.odaPrivateEndpointId : undefined;
            resourceInputs["protocol"] = state ? state.protocol : undefined;
            resourceInputs["scanListenerInfos"] = state ? state.scanListenerInfos : undefined;
            resourceInputs["scanListenerType"] = state ? state.scanListenerType : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as OdaPrivateEndpointScanProxyArgs | undefined;
            if ((!args || args.odaPrivateEndpointId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'odaPrivateEndpointId'");
            }
            if ((!args || args.protocol === undefined) && !opts.urn) {
                throw new Error("Missing required property 'protocol'");
            }
            if ((!args || args.scanListenerInfos === undefined) && !opts.urn) {
                throw new Error("Missing required property 'scanListenerInfos'");
            }
            if ((!args || args.scanListenerType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'scanListenerType'");
            }
            resourceInputs["odaPrivateEndpointId"] = args ? args.odaPrivateEndpointId : undefined;
            resourceInputs["protocol"] = args ? args.protocol : undefined;
            resourceInputs["scanListenerInfos"] = args ? args.scanListenerInfos : undefined;
            resourceInputs["scanListenerType"] = args ? args.scanListenerType : undefined;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(OdaPrivateEndpointScanProxy.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering OdaPrivateEndpointScanProxy resources.
 */
export interface OdaPrivateEndpointScanProxyState {
    /**
     * Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    odaPrivateEndpointId?: pulumi.Input<string>;
    /**
     * The protocol used for communication between client, scanProxy and RAC's scan listeners
     */
    protocol?: pulumi.Input<string>;
    /**
     * The FQDN/IPs and port information of customer's Real Application Cluster (RAC)'s SCAN listeners.
     */
    scanListenerInfos?: pulumi.Input<pulumi.Input<inputs.Oda.OdaPrivateEndpointScanProxyScanListenerInfo>[]>;
    /**
     * Type indicating whether Scan listener is specified by its FQDN or list of IPs 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    scanListenerType?: pulumi.Input<string>;
    /**
     * The current state of the ODA Private Endpoint Scan Proxy.
     */
    state?: pulumi.Input<string>;
    /**
     * When the resource was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a OdaPrivateEndpointScanProxy resource.
 */
export interface OdaPrivateEndpointScanProxyArgs {
    /**
     * Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    odaPrivateEndpointId: pulumi.Input<string>;
    /**
     * The protocol used for communication between client, scanProxy and RAC's scan listeners
     */
    protocol: pulumi.Input<string>;
    /**
     * The FQDN/IPs and port information of customer's Real Application Cluster (RAC)'s SCAN listeners.
     */
    scanListenerInfos: pulumi.Input<pulumi.Input<inputs.Oda.OdaPrivateEndpointScanProxyScanListenerInfo>[]>;
    /**
     * Type indicating whether Scan listener is specified by its FQDN or list of IPs 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    scanListenerType: pulumi.Input<string>;
}
