// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Identity Provider resource in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Get an Identity Provider
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testIdentityProvider = oci.Identity.getDomainsIdentityProvider({
 *     idcsEndpoint: data.oci_identity_domain.test_domain.url,
 *     identityProviderId: oci_identity_identity_provider.test_identity_provider.id,
 *     attributeSets: [],
 *     attributes: "",
 *     authorization: _var.identity_provider_authorization,
 *     resourceTypeSchemaVersion: _var.identity_provider_resource_type_schema_version,
 * });
 * ```
 */
export function getDomainsIdentityProvider(args: GetDomainsIdentityProviderArgs, opts?: pulumi.InvokeOptions): Promise<GetDomainsIdentityProviderResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Identity/getDomainsIdentityProvider:getDomainsIdentityProvider", {
        "attributeSets": args.attributeSets,
        "attributes": args.attributes,
        "authorization": args.authorization,
        "idcsEndpoint": args.idcsEndpoint,
        "identityProviderId": args.identityProviderId,
        "resourceTypeSchemaVersion": args.resourceTypeSchemaVersion,
    }, opts);
}

/**
 * A collection of arguments for invoking getDomainsIdentityProvider.
 */
export interface GetDomainsIdentityProviderArgs {
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
    identityProviderId: string;
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: string;
}

/**
 * A collection of values returned by getDomainsIdentityProvider.
 */
export interface GetDomainsIdentityProviderResult {
    /**
     * Assertion attribute name.
     */
    readonly assertionAttribute: string;
    readonly attributeSets?: string[];
    readonly attributes?: string;
    /**
     * HTTP binding to use for authentication requests.
     */
    readonly authnRequestBinding: string;
    readonly authorization?: string;
    /**
     * Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     */
    readonly compartmentOcid: string;
    /**
     * Correlation policy
     */
    readonly correlationPolicies: outputs.Identity.GetDomainsIdentityProviderCorrelationPolicy[];
    /**
     * A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     */
    readonly deleteInProgress: boolean;
    /**
     * Description
     */
    readonly description: string;
    /**
     * Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     */
    readonly domainOcid: string;
    /**
     * Set to true to indicate Partner enabled.
     */
    readonly enabled: boolean;
    /**
     * Encryption certificate
     */
    readonly encryptionCertificate: string;
    /**
     * An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer's tenant.
     */
    readonly externalId: string;
    /**
     * Identity Provider Icon URL.
     */
    readonly iconUrl: string;
    /**
     * Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
     */
    readonly id: string;
    /**
     * The User or App who created the Resource
     */
    readonly idcsCreatedBies: outputs.Identity.GetDomainsIdentityProviderIdcsCreatedBy[];
    readonly idcsEndpoint: string;
    /**
     * The User or App who modified the Resource
     */
    readonly idcsLastModifiedBies: outputs.Identity.GetDomainsIdentityProviderIdcsLastModifiedBy[];
    /**
     * The release number when the resource was upgraded.
     */
    readonly idcsLastUpgradedInRelease: string;
    /**
     * Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     */
    readonly idcsPreventedOperations: string[];
    readonly identityProviderId: string;
    /**
     * Identity Provider SSO URL
     */
    readonly idpSsoUrl: string;
    /**
     * Set to true to include the signing certificate in the signature.
     */
    readonly includeSigningCertInSignature: boolean;
    /**
     * Refers to every group of which a JIT-provisioned User should be a member.  Just-in-Time user-provisioning applies this static list when jitUserProvGroupStaticListEnabled:true.
     */
    readonly jitUserProvAssignedGroups: outputs.Identity.GetDomainsIdentityProviderJitUserProvAssignedGroup[];
    /**
     * Set to true to indicate JIT User Creation is enabled
     */
    readonly jitUserProvAttributeUpdateEnabled: boolean;
    /**
     * Assertion To User Mapping
     */
    readonly jitUserProvAttributes: outputs.Identity.GetDomainsIdentityProviderJitUserProvAttribute[];
    /**
     * Set to true to indicate JIT User Creation is enabled
     */
    readonly jitUserProvCreateUserEnabled: boolean;
    /**
     * Set to true to indicate JIT User Provisioning is enabled
     */
    readonly jitUserProvEnabled: boolean;
    /**
     * Set to true to indicate JIT User Provisioning Groups should be assigned based on assertion attribute
     */
    readonly jitUserProvGroupAssertionAttributeEnabled: boolean;
    /**
     * The default value is 'Overwrite', which tells Just-In-Time user-provisioning to replace any current group-assignments for a User with those assigned by assertions and/or those assigned statically. Specify 'Merge' if you want Just-In-Time user-provisioning to combine its group-assignments with those the user already has.
     */
    readonly jitUserProvGroupAssignmentMethod: string;
    /**
     * Property to indicate the mode of group mapping
     */
    readonly jitUserProvGroupMappingMode: string;
    /**
     * The list of mappings between the Identity Domain Group and the IDP group.
     */
    readonly jitUserProvGroupMappings: outputs.Identity.GetDomainsIdentityProviderJitUserProvGroupMapping[];
    /**
     * Name of the assertion attribute containing the users groups
     */
    readonly jitUserProvGroupSamlAttributeName: string;
    /**
     * Set to true to indicate JIT User Provisioning Groups should be assigned from a static list
     */
    readonly jitUserProvGroupStaticListEnabled: boolean;
    /**
     * Set to true to indicate ignoring absence of group while provisioning
     */
    readonly jitUserProvIgnoreErrorOnAbsentGroups: boolean;
    /**
     * HTTP binding to use for logout.
     */
    readonly logoutBinding: string;
    /**
     * Set to true to enable logout.
     */
    readonly logoutEnabled: boolean;
    /**
     * Logout request URL
     */
    readonly logoutRequestUrl: string;
    /**
     * Logout response URL
     */
    readonly logoutResponseUrl: string;
    /**
     * Metadata
     */
    readonly metadata: string;
    /**
     * A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     */
    readonly metas: outputs.Identity.GetDomainsIdentityProviderMeta[];
    /**
     * Default authentication request name ID format.
     */
    readonly nameIdFormat: string;
    /**
     * Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     */
    readonly ocid: string;
    /**
     * Unique name of the trusted Identity Provider.
     */
    readonly partnerName: string;
    /**
     * Provider ID
     */
    readonly partnerProviderId: string;
    /**
     * SAML SP authentication type.
     */
    readonly requestedAuthenticationContexts: string[];
    /**
     * This SP requires requests SAML IdP to enforce re-authentication.
     */
    readonly requireForceAuthn: boolean;
    /**
     * SAML SP must accept encrypted assertion only.
     */
    readonly requiresEncryptedAssertion: boolean;
    readonly resourceTypeSchemaVersion?: string;
    /**
     * SAML SP HoK Enabled.
     */
    readonly samlHoKrequired: boolean;
    /**
     * REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     */
    readonly schemas: string[];
    /**
     * The serviceInstanceIdentifier of the App that hosts this IdP. This value will match the opcServiceInstanceGUID of any service-instance that the IdP represents.
     */
    readonly serviceInstanceIdentifier: string;
    /**
     * Set to true to indicate whether to show IdP in login page or not.
     */
    readonly shownOnLoginPage: boolean;
    /**
     * Signature hash algorithm.
     */
    readonly signatureHashAlgorithm: string;
    /**
     * Signing certificate
     */
    readonly signingCertificate: string;
    /**
     * Succinct ID
     */
    readonly succinctId: string;
    /**
     * A list of tags on this resource.
     */
    readonly tags: outputs.Identity.GetDomainsIdentityProviderTag[];
    /**
     * Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     */
    readonly tenancyOcid: string;
    /**
     * The alternate Provider ID to be used as the Oracle Identity Cloud Service providerID (instead of the one in SamlSettings) when interacting with this IdP.
     */
    readonly tenantProviderId: string;
    /**
     * Identity Provider Type
     */
    readonly type: string;
    /**
     * Social Identity Provider Extension Schema
     */
    readonly urnietfparamsscimschemasoracleidcsextensionsocialIdentityProviders: outputs.Identity.GetDomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProvider[];
    /**
     * X509 Identity Provider Extension Schema
     */
    readonly urnietfparamsscimschemasoracleidcsextensionx509identityProviders: outputs.Identity.GetDomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionx509identityProvider[];
    /**
     * User mapping method.
     */
    readonly userMappingMethod: string;
    /**
     * This property specifies the userstore attribute value that must match the incoming assertion attribute value or the incoming nameid attribute value in order to identify the user during SSO.<br>You can construct the userMappingStoreAttribute value by specifying attributes from the Oracle Identity Cloud Service Core Users schema. For examples of how to construct the userMappingStoreAttribute value, see the <b>Example of a Request Body</b> section of the Examples tab for the <a href='./op-admin-v1-identityproviders-post.html'>POST</a> and <a href='./op-admin-v1-identityproviders-id-put.html'>PUT</a> methods of the /IdentityProviders endpoint.
     */
    readonly userMappingStoreAttribute: string;
}
/**
 * This data source provides details about a specific Identity Provider resource in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Get an Identity Provider
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testIdentityProvider = oci.Identity.getDomainsIdentityProvider({
 *     idcsEndpoint: data.oci_identity_domain.test_domain.url,
 *     identityProviderId: oci_identity_identity_provider.test_identity_provider.id,
 *     attributeSets: [],
 *     attributes: "",
 *     authorization: _var.identity_provider_authorization,
 *     resourceTypeSchemaVersion: _var.identity_provider_resource_type_schema_version,
 * });
 * ```
 */
export function getDomainsIdentityProviderOutput(args: GetDomainsIdentityProviderOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDomainsIdentityProviderResult> {
    return pulumi.output(args).apply((a: any) => getDomainsIdentityProvider(a, opts))
}

/**
 * A collection of arguments for invoking getDomainsIdentityProvider.
 */
export interface GetDomainsIdentityProviderOutputArgs {
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
    identityProviderId: pulumi.Input<string>;
    /**
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: pulumi.Input<string>;
}