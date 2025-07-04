// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Api Metadata resource in Oracle Cloud Infrastructure Apiaccesscontrol service.
 *
 * Gets information about a ApiMetadata.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testApiMetadata = oci.oci.getApiaccesscontrolApiMetadata({
 *     apiMetadataId: testApiMetadataOciApiaccesscontrolApiMetadata.id,
 * });
 * ```
 */
export function getApiaccesscontrolApiMetadata(args: GetApiaccesscontrolApiMetadataArgs, opts?: pulumi.InvokeOptions): Promise<GetApiaccesscontrolApiMetadataResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:oci/getApiaccesscontrolApiMetadata:getApiaccesscontrolApiMetadata", {
        "apiMetadataId": args.apiMetadataId,
    }, opts);
}

/**
 * A collection of arguments for invoking getApiaccesscontrolApiMetadata.
 */
export interface GetApiaccesscontrolApiMetadataArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the PrivilegedApiControl.
     */
    apiMetadataId: string;
}

/**
 * A collection of values returned by getApiaccesscontrolApiMetadata.
 */
export interface GetApiaccesscontrolApiMetadataResult {
    readonly apiMetadataId: string;
    /**
     * The name of the api to execute the api request.
     */
    readonly apiName: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * The operation Name of the api. The name must be unique.
     */
    readonly displayName: string;
    /**
     * ResourceType to which the apiMetadata belongs to.
     */
    readonly entityType: string;
    /**
     * List of the fields that is use while calling post or put for the data.
     */
    readonly fields: string[];
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * A message that describes the current state of the ApiMetadata in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * rest path of the api.
     */
    readonly path: string;
    /**
     * The service Name to which the api belongs to.
     */
    readonly serviceName: string;
    /**
     * The current state of the ApiMetadata.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The date and time the PrivilegedApiControl was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeCreated: string;
    /**
     * The date and time the PrivilegedApiControl was marked for delete, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeDeleted: string;
    /**
     * The date and time the PrivilegedApiControl was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Api Metadata resource in Oracle Cloud Infrastructure Apiaccesscontrol service.
 *
 * Gets information about a ApiMetadata.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testApiMetadata = oci.oci.getApiaccesscontrolApiMetadata({
 *     apiMetadataId: testApiMetadataOciApiaccesscontrolApiMetadata.id,
 * });
 * ```
 */
export function getApiaccesscontrolApiMetadataOutput(args: GetApiaccesscontrolApiMetadataOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetApiaccesscontrolApiMetadataResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:oci/getApiaccesscontrolApiMetadata:getApiaccesscontrolApiMetadata", {
        "apiMetadataId": args.apiMetadataId,
    }, opts);
}

/**
 * A collection of arguments for invoking getApiaccesscontrolApiMetadata.
 */
export interface GetApiaccesscontrolApiMetadataOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the PrivilegedApiControl.
     */
    apiMetadataId: pulumi.Input<string>;
}
