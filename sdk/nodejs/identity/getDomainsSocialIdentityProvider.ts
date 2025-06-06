// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Social Identity Provider resource in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Get a Social Identity Provider
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSocialIdentityProvider = oci.Identity.getDomainsSocialIdentityProvider({
 *     idcsEndpoint: testDomain.url,
 *     socialIdentityProviderId: testIdentityProvider.id,
 *     authorization: socialIdentityProviderAuthorization,
 *     resourceTypeSchemaVersion: socialIdentityProviderResourceTypeSchemaVersion,
 * });
 * ```
 */
export function getDomainsSocialIdentityProvider(args: GetDomainsSocialIdentityProviderArgs, opts?: pulumi.InvokeOptions): Promise<GetDomainsSocialIdentityProviderResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Identity/getDomainsSocialIdentityProvider:getDomainsSocialIdentityProvider", {
        "authorization": args.authorization,
        "idcsEndpoint": args.idcsEndpoint,
        "resourceTypeSchemaVersion": args.resourceTypeSchemaVersion,
        "socialIdentityProviderId": args.socialIdentityProviderId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDomainsSocialIdentityProvider.
 */
export interface GetDomainsSocialIdentityProviderArgs {
    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     */
    authorization?: string;
    /**
     * The basic endpoint for the identity domain
     */
    idcsEndpoint: string;
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: string;
    /**
     * ID of the resource
     */
    socialIdentityProviderId: string;
}

/**
 * A collection of values returned by getDomainsSocialIdentityProvider.
 */
export interface GetDomainsSocialIdentityProviderResult {
    /**
     * Social IDP Access token URL
     */
    readonly accessTokenUrl: string;
    /**
     * Whether account linking is enabled
     */
    readonly accountLinkingEnabled: boolean;
    /**
     * Admin scope to request
     */
    readonly adminScopes: string[];
    readonly authorization?: string;
    /**
     * Social IDP Authorization URL
     */
    readonly authzUrl: string;
    /**
     * Whether social auto redirect is enabled. The IDP policy should be configured with only one Social IDP, and without username/password selected.
     */
    readonly autoRedirectEnabled: boolean;
    /**
     * Whether the client credential is contained in payload
     */
    readonly clientCredentialInPayload: boolean;
    /**
     * Social IDP allowed clock skew time
     */
    readonly clockSkewInSeconds: number;
    /**
     * Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     */
    readonly compartmentOcid: string;
    /**
     * Social IDP Client Application Client ID
     */
    readonly consumerKey: string;
    /**
     * Social IDP Client Application Client Secret
     */
    readonly consumerSecret: string;
    /**
     * A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     */
    readonly deleteInProgress: boolean;
    /**
     * Social IDP description
     */
    readonly description: string;
    /**
     * Discovery URL
     */
    readonly discoveryUrl: string;
    /**
     * Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     */
    readonly domainOcid: string;
    /**
     * Whether the IDP is enabled or not
     */
    readonly enabled: boolean;
    /**
     * ICON URL for social idp
     */
    readonly iconUrl: string;
    /**
     * Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
     */
    readonly id: string;
    /**
     * Id attribute used for account linking
     */
    readonly idAttribute: string;
    /**
     * The User or App who created the Resource
     */
    readonly idcsCreatedBies: outputs.Identity.GetDomainsSocialIdentityProviderIdcsCreatedBy[];
    readonly idcsEndpoint: string;
    /**
     * The User or App who modified the Resource
     */
    readonly idcsLastModifiedBies: outputs.Identity.GetDomainsSocialIdentityProviderIdcsLastModifiedBy[];
    /**
     * The release number when the resource was upgraded.
     */
    readonly idcsLastUpgradedInRelease: string;
    /**
     * Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     */
    readonly idcsPreventedOperations: string[];
    /**
     * Lists the groups each social JIT-provisioned user is a member. Just-in-Time user-provisioning applies this static list when jitProvGroupStaticListEnabled:true.
     */
    readonly jitProvAssignedGroups: outputs.Identity.GetDomainsSocialIdentityProviderJitProvAssignedGroup[];
    /**
     * Set to true to indicate Social JIT User Provisioning Groups should be assigned from a static list
     */
    readonly jitProvGroupStaticListEnabled: boolean;
    /**
     * A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     */
    readonly metas: outputs.Identity.GetDomainsSocialIdentityProviderMeta[];
    /**
     * Social provider name
     */
    readonly name: string;
    /**
     * Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     */
    readonly ocid: string;
    /**
     * Social IDP User profile URL
     */
    readonly profileUrl: string;
    /**
     * redirect URL for social idp
     */
    readonly redirectUrl: string;
    /**
     * Social IDP Refresh token URL
     */
    readonly refreshTokenUrl: string;
    /**
     * Whether registration is enabled
     */
    readonly registrationEnabled: boolean;
    /**
     * Relay Param variable for Social IDP
     */
    readonly relayIdpParamMappings: outputs.Identity.GetDomainsSocialIdentityProviderRelayIdpParamMapping[];
    readonly resourceTypeSchemaVersion?: string;
    /**
     * REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     */
    readonly schemas: string[];
    /**
     * Scope to request
     */
    readonly scopes: string[];
    /**
     * Service Provider Name
     */
    readonly serviceProviderName: string;
    /**
     * Whether show on login
     */
    readonly showOnLogin: boolean;
    readonly socialIdentityProviderId: string;
    /**
     * Whether Social JIT Provisioning is enabled
     */
    readonly socialJitProvisioningEnabled: boolean;
    /**
     * Status
     */
    readonly status: string;
    /**
     * A list of tags on this resource.
     */
    readonly tags: outputs.Identity.GetDomainsSocialIdentityProviderTag[];
    /**
     * Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     */
    readonly tenancyOcid: string;
}
/**
 * This data source provides details about a specific Social Identity Provider resource in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Get a Social Identity Provider
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSocialIdentityProvider = oci.Identity.getDomainsSocialIdentityProvider({
 *     idcsEndpoint: testDomain.url,
 *     socialIdentityProviderId: testIdentityProvider.id,
 *     authorization: socialIdentityProviderAuthorization,
 *     resourceTypeSchemaVersion: socialIdentityProviderResourceTypeSchemaVersion,
 * });
 * ```
 */
export function getDomainsSocialIdentityProviderOutput(args: GetDomainsSocialIdentityProviderOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDomainsSocialIdentityProviderResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Identity/getDomainsSocialIdentityProvider:getDomainsSocialIdentityProvider", {
        "authorization": args.authorization,
        "idcsEndpoint": args.idcsEndpoint,
        "resourceTypeSchemaVersion": args.resourceTypeSchemaVersion,
        "socialIdentityProviderId": args.socialIdentityProviderId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDomainsSocialIdentityProvider.
 */
export interface GetDomainsSocialIdentityProviderOutputArgs {
    /**
     * The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
     */
    authorization?: pulumi.Input<string>;
    /**
     * The basic endpoint for the identity domain
     */
    idcsEndpoint: pulumi.Input<string>;
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: pulumi.Input<string>;
    /**
     * ID of the resource
     */
    socialIdentityProviderId: pulumi.Input<string>;
}
