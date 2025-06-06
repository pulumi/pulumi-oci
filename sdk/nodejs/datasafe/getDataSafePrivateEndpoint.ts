// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Data Safe Private Endpoint resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets the details of the specified Data Safe private endpoint.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataSafePrivateEndpoint = oci.DataSafe.getDataSafePrivateEndpoint({
 *     dataSafePrivateEndpointId: testDataSafePrivateEndpointOciDataSafeDataSafePrivateEndpoint.id,
 * });
 * ```
 */
export function getDataSafePrivateEndpoint(args: GetDataSafePrivateEndpointArgs, opts?: pulumi.InvokeOptions): Promise<GetDataSafePrivateEndpointResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataSafe/getDataSafePrivateEndpoint:getDataSafePrivateEndpoint", {
        "dataSafePrivateEndpointId": args.dataSafePrivateEndpointId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDataSafePrivateEndpoint.
 */
export interface GetDataSafePrivateEndpointArgs {
    /**
     * The OCID of the private endpoint.
     */
    dataSafePrivateEndpointId: string;
}

/**
 * A collection of values returned by getDataSafePrivateEndpoint.
 */
export interface GetDataSafePrivateEndpointResult {
    /**
     * The OCID of the compartment.
     */
    readonly compartmentId: string;
    readonly dataSafePrivateEndpointId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * The description of the private endpoint.
     */
    readonly description: string;
    /**
     * The display name of the private endpoint.
     */
    readonly displayName: string;
    /**
     * The three-label fully qualified domain name (FQDN) of the private endpoint. The customer VCN's DNS records are updated with this FQDN.
     */
    readonly endpointFqdn: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The OCID of the Data Safe private endpoint.
     */
    readonly id: string;
    /**
     * The OCIDs of the network security groups that the private endpoint belongs to.
     */
    readonly nsgIds: string[];
    /**
     * The OCID of the underlying private endpoint.
     */
    readonly privateEndpointId: string;
    /**
     * The private IP address of the private endpoint.
     */
    readonly privateEndpointIp: string;
    /**
     * The current state of the private endpoint.
     */
    readonly state: string;
    /**
     * The OCID of the subnet.
     */
    readonly subnetId: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The date and time the private endpoint was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeCreated: string;
    /**
     * The OCID of the VCN.
     */
    readonly vcnId: string;
}
/**
 * This data source provides details about a specific Data Safe Private Endpoint resource in Oracle Cloud Infrastructure Data Safe service.
 *
 * Gets the details of the specified Data Safe private endpoint.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataSafePrivateEndpoint = oci.DataSafe.getDataSafePrivateEndpoint({
 *     dataSafePrivateEndpointId: testDataSafePrivateEndpointOciDataSafeDataSafePrivateEndpoint.id,
 * });
 * ```
 */
export function getDataSafePrivateEndpointOutput(args: GetDataSafePrivateEndpointOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDataSafePrivateEndpointResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataSafe/getDataSafePrivateEndpoint:getDataSafePrivateEndpoint", {
        "dataSafePrivateEndpointId": args.dataSafePrivateEndpointId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDataSafePrivateEndpoint.
 */
export interface GetDataSafePrivateEndpointOutputArgs {
    /**
     * The OCID of the private endpoint.
     */
    dataSafePrivateEndpointId: pulumi.Input<string>;
}
