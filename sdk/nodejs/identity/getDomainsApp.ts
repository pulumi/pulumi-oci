// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific App resource in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Get an App
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testApp = oci.Identity.getDomainsApp({
 *     appId: oci_identity_domains_app.test_app.id,
 *     idcsEndpoint: data.oci_identity_domain.test_domain.url,
 *     attributeSets: ["all"],
 *     attributes: "",
 *     authorization: _var.app_authorization,
 *     resourceTypeSchemaVersion: _var.app_resource_type_schema_version,
 * });
 * ```
 */
export function getDomainsApp(args: GetDomainsAppArgs, opts?: pulumi.InvokeOptions): Promise<GetDomainsAppResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Identity/getDomainsApp:getDomainsApp", {
        "appId": args.appId,
        "attributeSets": args.attributeSets,
        "attributes": args.attributes,
        "authorization": args.authorization,
        "idcsEndpoint": args.idcsEndpoint,
        "resourceTypeSchemaVersion": args.resourceTypeSchemaVersion,
    }, opts);
}

/**
 * A collection of arguments for invoking getDomainsApp.
 */
export interface GetDomainsAppArgs {
    /**
     * ID of the resource
     */
    appId: string;
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
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: string;
}

/**
 * A collection of values returned by getDomainsApp.
 */
export interface GetDomainsAppResult {
    /**
     * Access token expiry
     */
    readonly accessTokenExpiry: number;
    /**
     * Accounts of App
     */
    readonly accounts: outputs.Identity.GetDomainsAppAccount[];
    /**
     * If true, this App is able to participate in runtime services, such as automatic-login, OAuth, and SAML. If false, all runtime services are disabled for this App, and only administrative operations can be performed.
     */
    readonly active: boolean;
    /**
     * A list of AppRoles defined by this UnmanagedApp. Membership in each of these AppRoles confers administrative privilege within this App.
     */
    readonly adminRoles: outputs.Identity.GetDomainsAppAdminRole[];
    /**
     * Each value of this internal attribute refers to an Oracle Public Cloud infrastructure App on which this App depends.
     */
    readonly aliasApps: outputs.Identity.GetDomainsAppAliasApp[];
    /**
     * If true, indicates that the system should allow all URL-schemes within each value of the 'redirectUris' attribute.  Also indicates that the system should not attempt to confirm that each value of the 'redirectUris' attribute is a valid URI.  In particular, the system should not confirm that the domain component of the URI is a top-level domain and the system should not confirm that the hostname portion is a valid system that is reachable over the network.
     */
    readonly allUrlSchemesAllowed: boolean;
    /**
     * If true, any managed App that is based on this template is checked for access control that is, access to this app is subject to successful authorization at SSO service, viz. app grants to start with.
     */
    readonly allowAccessControl: boolean;
    /**
     * If true, indicates that the Refresh Token is allowed when this App acts as an OAuth Resource.
     */
    readonly allowOffline: boolean;
    /**
     * List of grant-types that this App is allowed to use when it acts as an OAuthClient.
     */
    readonly allowedGrants: string[];
    /**
     * OPTIONAL. Required only when this App acts as an OAuthClient. Supported values are 'introspect' and 'onBehalfOfUser'. The value 'introspect' allows the client to look inside the access-token. The value 'onBehalfOfUser' overrides how the client's privileges are combined with the privileges of the Subject User. Ordinarily, authorization calculates the set of effective privileges as the intersection of the client's privileges and the user's privileges. The value 'onBehalfOf' indicates that authorization should ignore the privileges of the client and use only the user's privileges to calculate the effective privileges.
     */
    readonly allowedOperations: string[];
    /**
     * A list of scopes (exposed by this App or by other Apps) that this App is allowed to access when it acts as an OAuthClient.
     */
    readonly allowedScopes: outputs.Identity.GetDomainsAppAllowedScope[];
    /**
     * A list of tags, acting as an OAuthClient, this App is allowed to access.
     */
    readonly allowedTags: outputs.Identity.GetDomainsAppAllowedTag[];
    /**
     * Application icon.
     */
    readonly appIcon: string;
    /**
     * The id of the App that defines this AppRole, which is granted to this App. The App that defines the AppRole acts as the producer; the App to which the AppRole is granted acts as a consumer.
     */
    readonly appId: string;
    /**
     * App Sign-on Policy.
     */
    readonly appSignonPolicies: outputs.Identity.GetDomainsAppAppSignonPolicy[];
    /**
     * Application thumbnail.
     */
    readonly appThumbnail: string;
    /**
     * Network Perimeter
     */
    readonly appsNetworkPerimeters: outputs.Identity.GetDomainsAppAppsNetworkPerimeter[];
    /**
     * OPCService facet of the application.
     */
    readonly asOpcServices: outputs.Identity.GetDomainsAppAsOpcService[];
    /**
     * Label for the attribute to be shown in the UI.
     */
    readonly attrRenderingMetadatas: outputs.Identity.GetDomainsAppAttrRenderingMetadata[];
    readonly attributeSets?: string[];
    readonly attributes?: string;
    /**
     * The base URI for all of the scopes defined in this App. The value of 'audience' is combined with the 'value' of each scope to form an 'fqs' or fully qualified scope.
     */
    readonly audience: string;
    readonly authorization?: string;
    /**
     * Application template on which the application is based.
     */
    readonly basedOnTemplates: outputs.Identity.GetDomainsAppBasedOnTemplate[];
    /**
     * If true, indicates that consent should be skipped for all scopes
     */
    readonly bypassConsent: boolean;
    /**
     * Callback Service URL
     */
    readonly callbackServiceUrl: string;
    /**
     * Each value of this attribute represent a certificate that this App uses when it acts as an OAuthClient.
     */
    readonly certificates: outputs.Identity.GetDomainsAppCertificate[];
    /**
     * Network Perimeters checking mode
     */
    readonly clientIpChecking: string;
    /**
     * This value is the credential of this App, which this App supplies as a password when this App authenticates to the Oracle Public Cloud infrastructure. This value is also the client secret of this App when it acts as an OAuthClient.
     */
    readonly clientSecret: string;
    /**
     * Specifies the type of access that this App has when it acts as an OAuthClient.
     */
    readonly clientType: string;
    /**
     * A collection of arbitrary properties that scope the privileges of a cloud-control App.
     */
    readonly cloudControlProperties: outputs.Identity.GetDomainsAppCloudControlProperty[];
    /**
     * Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
     */
    readonly compartmentOcid: string;
    /**
     * Contact Email Address
     */
    readonly contactEmailAddress: string;
    /**
     * Service Names allow to use Oracle Cloud Infrastructure signature for client authentication instead of client credentials
     */
    readonly delegatedServiceNames: string[];
    /**
     * A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
     */
    readonly deleteInProgress: boolean;
    /**
     * The description of the AppRole.
     */
    readonly description: string;
    /**
     * Indicates whether the application is allowed to be access using kmsi token.
     */
    readonly disableKmsiTokenAuthentication: boolean;
    /**
     * Display name of the flatfile bundle configuration property. This attribute maps to \"displayName\" attribute in \"ConfigurationProperty\" in ICF.
     */
    readonly displayName: string;
    /**
     * Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
     */
    readonly domainOcid: string;
    /**
     * App attributes editable by subject
     */
    readonly editableAttributes: outputs.Identity.GetDomainsAppEditableAttribute[];
    /**
     * This attribute specifies the URL of the page to which an application will redirect an end-user in case of error.
     */
    readonly errorPageUrl: string;
    /**
     * A list of AppRoles that are granted to this App (and that are defined by other Apps). Within the Oracle Public Cloud infrastructure, this allows AppID-based association. Such an association allows this App to act as a consumer and thus to access resources of another App that acts as a producer.
     */
    readonly grantedAppRoles: outputs.Identity.GetDomainsAppGrantedAppRole[];
    /**
     * Grants assigned to the app
     */
    readonly grants: outputs.Identity.GetDomainsAppGrant[];
    /**
     * Hashed Client Secret. This hash-value is used to verify the 'clientSecret' credential of this App
     */
    readonly hashedClientSecret: string;
    /**
     * Home Page URL
     */
    readonly homePageUrl: string;
    /**
     * URL of application icon.
     */
    readonly icon: string;
    /**
     * Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
     */
    readonly id: string;
    /**
     * Encryption Alogrithm to use for encrypting ID token.
     */
    readonly idTokenEncAlgo: string;
    /**
     * The User or App who created the Resource
     */
    readonly idcsCreatedBies: outputs.Identity.GetDomainsAppIdcsCreatedBy[];
    readonly idcsEndpoint: string;
    /**
     * The User or App who modified the Resource
     */
    readonly idcsLastModifiedBies: outputs.Identity.GetDomainsAppIdcsLastModifiedBy[];
    /**
     * The release number when the resource was upgraded.
     */
    readonly idcsLastUpgradedInRelease: string;
    /**
     * Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
     */
    readonly idcsPreventedOperations: string[];
    /**
     * A list of IdentityProvider assigned to app. A user trying to access this app will be automatically redirected to configured IdP during the authentication phase, before being able to access App.
     */
    readonly identityProviders: outputs.Identity.GetDomainsAppIdentityProvider[];
    /**
     * IDP Policy.
     */
    readonly idpPolicies: outputs.Identity.GetDomainsAppIdpPolicy[];
    /**
     * If true, this App is an internal infrastructure App.
     */
    readonly infrastructure: boolean;
    /**
     * If true, this App is an AliasApp and it cannot be granted to an end-user directly.
     */
    readonly isAliasApp: boolean;
    /**
     * If true, this application acts as database service Application
     */
    readonly isDatabaseService: boolean;
    /**
     * If true, this app acts as Enterprise app with Authentication and URL Authz policy.
     */
    readonly isEnterpriseApp: boolean;
    /**
     * If true, this application acts as FormFill Application
     */
    readonly isFormFill: boolean;
    /**
     * If true, indicates that this App supports Kerberos Authentication
     */
    readonly isKerberosRealm: boolean;
    /**
     * If true, this App allows runtime services to log end users into this App automatically.
     */
    readonly isLoginTarget: boolean;
    /**
     * If true, indicates that access to this App requires an account. That is, in order to log in to the App, a User must use an application-specific identity that is maintained in the remote identity-repository of that App.
     */
    readonly isManagedApp: boolean;
    /**
     * If true, indicates that the App should be visible in each end-user's mobile application.
     */
    readonly isMobileTarget: boolean;
    /**
     * If true, indicates the app is used for multicloud service integration.
     */
    readonly isMulticloudServiceApp: boolean;
    /**
     * If true, this application acts as an OAuth Client
     */
    readonly isOauthClient: boolean;
    /**
     * If true, indicates that this application acts as an OAuth Resource.
     */
    readonly isOauthResource: boolean;
    /**
     * This flag indicates if the App is capable of validating obligations with the token for allowing access to the App.
     */
    readonly isObligationCapable: boolean;
    /**
     * If true, this application is an Oracle Public Cloud service-instance.
     */
    readonly isOpcService: boolean;
    /**
     * If true, this application acts as an Radius App
     */
    readonly isRadiusApp: boolean;
    /**
     * If true, then this App acts as a SAML Service Provider.
     */
    readonly isSamlServiceProvider: boolean;
    /**
     * If true, indicates that this application accepts an Oracle Cloud Identity Service User as a login-identity (does not require an account) and relies for authorization on the User's memberships in AppRoles.
     */
    readonly isUnmanagedApp: boolean;
    /**
     * If true, the webtier policy is active
     */
    readonly isWebTierPolicy: boolean;
    /**
     * The URL of the landing page for this App, which is the first page that an end user should see if runtime services log that end user in to this App automatically.
     */
    readonly landingPageUrl: string;
    /**
     * This attribute specifies the callback URL for the social linking operation.
     */
    readonly linkingCallbackUrl: string;
    /**
     * The protocol that runtime services will use to log end users in to this App automatically. If 'OIDC', then runtime services use the OpenID Connect protocol. If 'SAML', then runtime services use Security Assertion Markup Language protocol.
     */
    readonly loginMechanism: string;
    /**
     * This attribute specifies the URL of the page that the App uses when an end-user signs in to that App.
     */
    readonly loginPageUrl: string;
    /**
     * This attribute specifies the URL of the page that the App uses when an end-user signs out.
     */
    readonly logoutPageUrl: string;
    /**
     * OAuth will use this URI to logout if this App wants to participate in SSO, and if this App's session gets cleared as part of global logout. Note: This attribute is used only if this App acts as an OAuthClient.
     */
    readonly logoutUri: string;
    /**
     * A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
     */
    readonly metas: outputs.Identity.GetDomainsAppMeta[];
    /**
     * Indicates whether the application is billed as an OPCService. If true, customer is not billed for runtime operations of the app.
     */
    readonly meterAsOpcService: boolean;
    /**
     * If true, this App was migrated from an earlier version of Oracle Public Cloud infrastructure (and may therefore require special handling from runtime services such as OAuth or SAML). If false, this App requires no special handling from runtime services.
     */
    readonly migrated: boolean;
    /**
     * The attribute represents the name of the attribute that will be used in the Security Assertion Markup Language (SAML) assertion
     */
    readonly name: string;
    /**
     * Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
     */
    readonly ocid: string;
    /**
     * Each value of this attribute is the URI of a landing page within this App. It is used only when this App, acting as an OAuthClient, initiates the logout flow and wants to be redirected back to one of its landing pages.
     */
    readonly postLogoutRedirectUris: string[];
    /**
     * Privacy Policy URL
     */
    readonly privacyPolicyUrl: string;
    /**
     * Application Logo URL
     */
    readonly productLogoUrl: string;
    /**
     * Product Name
     */
    readonly productName: string;
    /**
     * A list of secondary audiences--additional URIs to be added automatically to any OAuth token that allows access to this App. Note: This attribute is used mainly for backward compatibility in certain Oracle Public Cloud Apps.
     */
    readonly protectableSecondaryAudiences: outputs.Identity.GetDomainsAppProtectableSecondaryAudience[];
    /**
     * RADIUS Policy assigned to this application.
     */
    readonly radiusPolicies: outputs.Identity.GetDomainsAppRadiusPolicy[];
    /**
     * If true, this App requires an upgrade and mandates attention from application administrator. The flag is used by UI to indicate this app is ready to upgrade.
     */
    readonly readyToUpgrade: boolean;
    /**
     * OPTIONAL. Each value is a URI within this App. This attribute is required when this App acts as an OAuthClient and is involved in three-legged flows (authorization-code flows).
     */
    readonly redirectUris: string[];
    /**
     * Expiry-time in seconds for a Refresh Token.  Any token that allows access to this App, once refreshed, will expire after the specified duration.
     */
    readonly refreshTokenExpiry: number;
    readonly resourceTypeSchemaVersion?: string;
    /**
     * An attribute that refers to the SAML Service Provider that runtime services will use to log an end user in to this App automatically. Note that this will be used only if the loginMechanism is 'SAML'.
     */
    readonly samlServiceProviders: outputs.Identity.GetDomainsAppSamlServiceProvider[];
    /**
     * REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
     */
    readonly schemas: string[];
    /**
     * Scopes defined by this App. Used when this App acts as an OAuth Resource.
     */
    readonly scopes: outputs.Identity.GetDomainsAppScope[];
    /**
     * A list of secondary audiences--additional URIs to be added automatically to any OAuth token that allows access to this App. Note: This attribute is used mainly for backward compatibility in certain Oracle Public Cloud Apps.
     */
    readonly secondaryAudiences: string[];
    /**
     * Custom attribute that is required to compute other attribute values during app creation.
     */
    readonly serviceParams: outputs.Identity.GetDomainsAppServiceParam[];
    /**
     * This Uniform Resource Name (URN) value identifies the type of Oracle Public Cloud service of which this app is an instance.
     */
    readonly serviceTypeUrn: string;
    /**
     * This value specifies the version of the Oracle Public Cloud service of which this App is an instance
     */
    readonly serviceTypeVersion: string;
    /**
     * If true, this app will be displayed in the MyApps page of each end-user who has access to the App.
     */
    readonly showInMyApps: boolean;
    /**
     * Sign-on Policy.
     */
    readonly signonPolicies: outputs.Identity.GetDomainsAppSignonPolicy[];
    /**
     * A list of tags on this resource.
     */
    readonly tags: outputs.Identity.GetDomainsAppTag[];
    /**
     * Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
     */
    readonly tenancyOcid: string;
    /**
     * Terms of Service URL
     */
    readonly termsOfServiceUrl: string;
    /**
     * Terms Of Use.
     */
    readonly termsOfUses: outputs.Identity.GetDomainsAppTermsOfUse[];
    /**
     * Trust Policies.
     */
    readonly trustPolicies: outputs.Identity.GetDomainsAppTrustPolicy[];
    /**
     * Indicates the scope of trust for this App when acting as an OAuthClient. A value of 'Explicit' indicates that the App is allowed to access only the scopes of OAuthResources that are explicitly specified as 'allowedScopes'. A value of 'Account' indicates that the App is allowed implicitly to access any scope of any OAuthResource within the same Oracle Cloud Account. A value of 'Tags' indicates that the App is allowed to access any scope of any OAuthResource with a matching tag within the same Oracle Cloud Account. A value of 'Default' indicates that the Tenant default trust scope configured in the Tenant Settings is used.
     */
    readonly trustScope: string;
    /**
     * Oracle Cloud Infrastructure Tags.
     */
    readonly urnietfparamsscimschemasoracleidcsextensionOciTags: outputs.Identity.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTag[];
    /**
     * This extension provides attributes for database service facet of an App
     */
    readonly urnietfparamsscimschemasoracleidcsextensiondbcsApps: outputs.Identity.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensiondbcsApp[];
    /**
     * This extension defines the Enterprise App related attributes.
     */
    readonly urnietfparamsscimschemasoracleidcsextensionenterpriseAppApps: outputs.Identity.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionenterpriseAppApp[];
    /**
     * This extension provides attributes for Form-Fill facet of App
     */
    readonly urnietfparamsscimschemasoracleidcsextensionformFillAppApps: outputs.Identity.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppApp[];
    /**
     * This extension provides attributes for Form-Fill facet of AppTemplate
     */
    readonly urnietfparamsscimschemasoracleidcsextensionformFillAppTemplateAppTemplates: outputs.Identity.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionformFillAppTemplateAppTemplate[];
    /**
     * Kerberos Realm
     */
    readonly urnietfparamsscimschemasoracleidcsextensionkerberosRealmApps: outputs.Identity.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionkerberosRealmApp[];
    /**
     * Managed App
     */
    readonly urnietfparamsscimschemasoracleidcsextensionmanagedappApps: outputs.Identity.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappApp[];
    /**
     * This extension defines attributes specific to Apps that represent instances of Multicloud Service App
     */
    readonly urnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppApps: outputs.Identity.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionmulticloudServiceAppApp[];
    /**
     * This extension defines attributes specific to Apps that represent instances of an Oracle Public Cloud (OPC) service.
     */
    readonly urnietfparamsscimschemasoracleidcsextensionopcServiceApps: outputs.Identity.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionopcServiceApp[];
    /**
     * This extension defines attributes specific to Apps that represent instances of Radius App.
     */
    readonly urnietfparamsscimschemasoracleidcsextensionradiusAppApps: outputs.Identity.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionradiusAppApp[];
    /**
     * Requestable App
     */
    readonly urnietfparamsscimschemasoracleidcsextensionrequestableApps: outputs.Identity.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionrequestableApp[];
    /**
     * This extension defines attributes related to the Service Providers configuration.
     */
    readonly urnietfparamsscimschemasoracleidcsextensionsamlServiceProviderApps: outputs.Identity.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderApp[];
    /**
     * WebTier Policy
     */
    readonly urnietfparamsscimschemasoracleidcsextensionwebTierPolicyApps: outputs.Identity.GetDomainsAppUrnietfparamsscimschemasoracleidcsextensionwebTierPolicyApp[];
    /**
     * A list of AppRoles defined by this UnmanagedApp. Membership in each of these AppRoles confers end-user privilege within this App.
     */
    readonly userRoles: outputs.Identity.GetDomainsAppUserRole[];
}
/**
 * This data source provides details about a specific App resource in Oracle Cloud Infrastructure Identity Domains service.
 *
 * Get an App
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testApp = oci.Identity.getDomainsApp({
 *     appId: oci_identity_domains_app.test_app.id,
 *     idcsEndpoint: data.oci_identity_domain.test_domain.url,
 *     attributeSets: ["all"],
 *     attributes: "",
 *     authorization: _var.app_authorization,
 *     resourceTypeSchemaVersion: _var.app_resource_type_schema_version,
 * });
 * ```
 */
export function getDomainsAppOutput(args: GetDomainsAppOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDomainsAppResult> {
    return pulumi.output(args).apply((a: any) => getDomainsApp(a, opts))
}

/**
 * A collection of arguments for invoking getDomainsApp.
 */
export interface GetDomainsAppOutputArgs {
    /**
     * ID of the resource
     */
    appId: pulumi.Input<string>;
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
     * An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
     */
    resourceTypeSchemaVersion?: pulumi.Input<string>;
}