// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Private Endpoint resource in Oracle Cloud Infrastructure Resource Manager service.
 *
 * Gets the specified private endpoint.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testPrivateEndpoint = oci.ResourceManager.getPrivateEndpoint({
 *     privateEndpointId: testPrivateEndpointOciResourcemanagerPrivateEndpoint.id,
 * });
 * ```
 */
export function getPrivateEndpoint(args: GetPrivateEndpointArgs, opts?: pulumi.InvokeOptions): Promise<GetPrivateEndpointResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ResourceManager/getPrivateEndpoint:getPrivateEndpoint", {
        "privateEndpointId": args.privateEndpointId,
    }, opts);
}

/**
 * A collection of arguments for invoking getPrivateEndpoint.
 */
export interface GetPrivateEndpointArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint.
     */
    privateEndpointId: string;
}

/**
 * A collection of values returned by getPrivateEndpoint.
 */
export interface GetPrivateEndpointResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing this private endpoint details.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * Description of the private endpoint. Avoid entering confidential information.
     */
    readonly description: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * DNS Proxy forwards any DNS FQDN queries over into the consumer DNS resolver if the DNS FQDN is included in the dns zones list otherwise it goes to service provider VCN resolver.
     */
    readonly dnsZones: string[];
    /**
     * Free-form tags associated with the resource. Each tag is a key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * Unique identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the private endpoint details.
     */
    readonly id: string;
    /**
     * When `true`, allows the private endpoint to be used with a configuration source provider.
     */
    readonly isUsedWithConfigurationSourceProvider: boolean;
    /**
     * An array of network security groups (NSG) that the customer can optionally provide.
     */
    readonly nsgIdLists: string[];
    readonly privateEndpointId: string;
    /**
     * The source IPs which resource manager service will use to connect to customer's network. Automatically assigned by Resource Manager Service.
     */
    readonly sourceIps: string[];
    /**
     * The current lifecycle state of the private endpoint.
     */
    readonly state: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet within the VCN for the private endpoint.
     */
    readonly subnetId: string;
    /**
     * The date and time at which the private endpoint was created. Format is defined by RFC3339. Example: `2020-11-25T21:10:29.600Z`
     */
    readonly timeCreated: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN for the private endpoint.
     */
    readonly vcnId: string;
}
/**
 * This data source provides details about a specific Private Endpoint resource in Oracle Cloud Infrastructure Resource Manager service.
 *
 * Gets the specified private endpoint.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testPrivateEndpoint = oci.ResourceManager.getPrivateEndpoint({
 *     privateEndpointId: testPrivateEndpointOciResourcemanagerPrivateEndpoint.id,
 * });
 * ```
 */
export function getPrivateEndpointOutput(args: GetPrivateEndpointOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetPrivateEndpointResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ResourceManager/getPrivateEndpoint:getPrivateEndpoint", {
        "privateEndpointId": args.privateEndpointId,
    }, opts);
}

/**
 * A collection of arguments for invoking getPrivateEndpoint.
 */
export interface GetPrivateEndpointOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint.
     */
    privateEndpointId: pulumi.Input<string>;
}
