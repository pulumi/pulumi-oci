// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific My Customer Secret Key resource in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Get user's customer secret key
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMyCustomerSecretKey = oci.Identity.getDomainsMyCustomerSecretKey({
 *     idcsEndpoint: data.oci_identity_domain.test_domain.url,
 *     myCustomerSecretKeyId: oci_identity_customer_secret_key.test_customer_secret_key.id,
 *     authorization: _var.my_customer_secret_key_authorization,
 *     resourceTypeSchemaVersion: _var.my_customer_secret_key_resource_type_schema_version,
 * });
 * ```
 */
export function getDomainsMyCustomerSecretKey(args: GetDomainsMyCustomerSecretKeyArgs, opts?: pulumi.InvokeOptions): Promise<GetDomainsMyCustomerSecretKeyResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Identity/getDomainsMyCustomerSecretKey:getDomainsMyCustomerSecretKey", {
        "authorization": args.authorization,
        "idcsEndpoint": args.idcsEndpoint,
        "myCustomerSecretKeyId": args.myCustomerSecretKeyId,
        "resourceTypeSchemaVersion": args.resourceTypeSchemaVersion,
    }, opts);
}

/**
 * A collection of arguments for invoking getDomainsMyCustomerSecretKey.
 */
export interface GetDomainsMyCustomerSecretKeyArgs {
    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     */
    authorization?: string;
    /**
     * The basic endpoint for the identity domain
     */
    idcsEndpoint: string;
    /**
     * ID of the resource
     */
    myCustomerSecretKeyId: string;
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: string;
}

/**
 * A collection of values returned by getDomainsMyCustomerSecretKey.
 */
export interface GetDomainsMyCustomerSecretKeyResult {
    /**
     * Access key
     */
    readonly accessKey: string;
    readonly authorization?: string;
    /**
     * Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     */
    readonly compartmentOcid: string;
    /**
     * A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     */
    readonly deleteInProgress: boolean;
    /**
     * Description
     */
    readonly description: string;
    /**
     * Display Name
     */
    readonly displayName: string;
    /**
     * Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     */
    readonly domainOcid: string;
    /**
     * User credential expires on
     */
    readonly expiresOn: string;
    /**
     * Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
     */
    readonly id: string;
    /**
     * The User or App who created the Resource
     */
    readonly idcsCreatedBies: outputs.Identity.GetDomainsMyCustomerSecretKeyIdcsCreatedBy[];
    readonly idcsEndpoint: string;
    /**
     * The User or App who modified the Resource
     */
    readonly idcsLastModifiedBies: outputs.Identity.GetDomainsMyCustomerSecretKeyIdcsLastModifiedBy[];
    /**
     * The release number when the resource was upgraded.
     */
    readonly idcsLastUpgradedInRelease: string;
    /**
     * Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     */
    readonly idcsPreventedOperations: string[];
    /**
     * A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     */
    readonly metas: outputs.Identity.GetDomainsMyCustomerSecretKeyMeta[];
    readonly myCustomerSecretKeyId: string;
    /**
     * User's ocid
     */
    readonly ocid: string;
    readonly resourceTypeSchemaVersion?: string;
    /**
     * REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     */
    readonly schemas: string[];
    /**
     * User credential status
     */
    readonly status: string;
    /**
     * A list of tags on this resource.
     */
    readonly tags: outputs.Identity.GetDomainsMyCustomerSecretKeyTag[];
    /**
     * Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     */
    readonly tenancyOcid: string;
    /**
     * User linked to customer secret key
     */
    readonly users: outputs.Identity.GetDomainsMyCustomerSecretKeyUser[];
}
/**
 * This data source provides details about a specific My Customer Secret Key resource in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Get user's customer secret key
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMyCustomerSecretKey = oci.Identity.getDomainsMyCustomerSecretKey({
 *     idcsEndpoint: data.oci_identity_domain.test_domain.url,
 *     myCustomerSecretKeyId: oci_identity_customer_secret_key.test_customer_secret_key.id,
 *     authorization: _var.my_customer_secret_key_authorization,
 *     resourceTypeSchemaVersion: _var.my_customer_secret_key_resource_type_schema_version,
 * });
 * ```
 */
export function getDomainsMyCustomerSecretKeyOutput(args: GetDomainsMyCustomerSecretKeyOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDomainsMyCustomerSecretKeyResult> {
    return pulumi.output(args).apply((a: any) => getDomainsMyCustomerSecretKey(a, opts))
}

/**
 * A collection of arguments for invoking getDomainsMyCustomerSecretKey.
 */
export interface GetDomainsMyCustomerSecretKeyOutputArgs {
    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     */
    authorization?: pulumi.Input<string>;
    /**
     * The basic endpoint for the identity domain
     */
    idcsEndpoint: pulumi.Input<string>;
    /**
     * ID of the resource
     */
    myCustomerSecretKeyId: pulumi.Input<string>;
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: pulumi.Input<string>;
}