// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Identity Setting resource in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Get an Identity setting.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testIdentitySetting = oci.Identity.getDomainsIdentitySetting({
 *     idcsEndpoint: data.oci_identity_domain.test_domain.url,
 *     identitySettingId: oci_identity_domains_identity_setting.test_identity_setting.id,
 *     attributeSets: ["all"],
 *     attributes: "",
 *     authorization: _var.identity_setting_authorization,
 *     resourceTypeSchemaVersion: _var.identity_setting_resource_type_schema_version,
 * });
 * ```
 */
export function getDomainsIdentitySetting(args: GetDomainsIdentitySettingArgs, opts?: pulumi.InvokeOptions): Promise<GetDomainsIdentitySettingResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Identity/getDomainsIdentitySetting:getDomainsIdentitySetting", {
        "attributeSets": args.attributeSets,
        "attributes": args.attributes,
        "authorization": args.authorization,
        "idcsEndpoint": args.idcsEndpoint,
        "identitySettingId": args.identitySettingId,
        "resourceTypeSchemaVersion": args.resourceTypeSchemaVersion,
    }, opts);
}

/**
 * A collection of arguments for invoking getDomainsIdentitySetting.
 */
export interface GetDomainsIdentitySettingArgs {
    /**
     * A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     */
    attributeSets?: string[];
    /**
     * A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     */
    attributes?: string;
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
    identitySettingId: string;
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: string;
}

/**
 * A collection of values returned by getDomainsIdentitySetting.
 */
export interface GetDomainsIdentitySettingResult {
    readonly attributeSets?: string[];
    readonly attributes?: string;
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
     * Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     */
    readonly domainOcid: string;
    /**
     * Indicates whether to show the 'user-is-locked' message during authentication if the user is already locked. The default value is false, which tells the system to show a generic 'authentication-failure' message. This is the most secure behavior. If the option is set to true, the system shows a more detailed 'error-message' that says the user is locked. This is more helpful but is less secure, for example, because the difference in error-messages could be used to determine which usernames exist and which do not.
     */
    readonly emitLockedMessageWhenUserIsLocked: boolean;
    /**
     * An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer's tenant.
     */
    readonly externalId: string;
    /**
     * Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
     */
    readonly id: string;
    /**
     * The User or App who created the Resource
     */
    readonly idcsCreatedBies: outputs.Identity.GetDomainsIdentitySettingIdcsCreatedBy[];
    readonly idcsEndpoint: string;
    /**
     * The User or App who modified the Resource
     */
    readonly idcsLastModifiedBies: outputs.Identity.GetDomainsIdentitySettingIdcsLastModifiedBy[];
    /**
     * The release number when the resource was upgraded.
     */
    readonly idcsLastUpgradedInRelease: string;
    /**
     * Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     */
    readonly idcsPreventedOperations: string[];
    readonly identitySettingId: string;
    /**
     * A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     */
    readonly metas: outputs.Identity.GetDomainsIdentitySettingMeta[];
    /**
     * Whether to allow users to update their own profile.
     */
    readonly myProfiles: outputs.Identity.GetDomainsIdentitySettingMyProfile[];
    /**
     * Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     */
    readonly ocid: string;
    /**
     * A list of Posix Gid settings.
     */
    readonly posixGids: outputs.Identity.GetDomainsIdentitySettingPosixGid[];
    /**
     * A list of Posix Uid settings.
     */
    readonly posixUids: outputs.Identity.GetDomainsIdentitySettingPosixUid[];
    /**
     * Indicates whether the primary email is required.
     */
    readonly primaryEmailRequired: boolean;
    /**
     * Indicates whether to remove non-RFC5322 compliant emails before creating a user.
     */
    readonly removeInvalidEmails: boolean;
    readonly resourceTypeSchemaVersion?: string;
    /**
     * **Added In:** 2302092332
     */
    readonly returnInactiveOverLockedMessage: boolean;
    /**
     * REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     */
    readonly schemas: string[];
    /**
     * A list of tags on this resource.
     */
    readonly tags: outputs.Identity.GetDomainsIdentitySettingTag[];
    /**
     * Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     */
    readonly tenancyOcid: string;
    /**
     * A list of tokens and their expiry length.
     */
    readonly tokens: outputs.Identity.GetDomainsIdentitySettingToken[];
    /**
     * Indicates whether a user is allowed to change their own recovery email.
     */
    readonly userAllowedToSetRecoveryEmail: boolean;
}
/**
 * This data source provides details about a specific Identity Setting resource in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Get an Identity setting.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testIdentitySetting = oci.Identity.getDomainsIdentitySetting({
 *     idcsEndpoint: data.oci_identity_domain.test_domain.url,
 *     identitySettingId: oci_identity_domains_identity_setting.test_identity_setting.id,
 *     attributeSets: ["all"],
 *     attributes: "",
 *     authorization: _var.identity_setting_authorization,
 *     resourceTypeSchemaVersion: _var.identity_setting_resource_type_schema_version,
 * });
 * ```
 */
export function getDomainsIdentitySettingOutput(args: GetDomainsIdentitySettingOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDomainsIdentitySettingResult> {
    return pulumi.output(args).apply((a: any) => getDomainsIdentitySetting(a, opts))
}

/**
 * A collection of arguments for invoking getDomainsIdentitySetting.
 */
export interface GetDomainsIdentitySettingOutputArgs {
    /**
     * A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
     */
    attributeSets?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
     */
    attributes?: pulumi.Input<string>;
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
    identitySettingId: pulumi.Input<string>;
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: pulumi.Input<string>;
}