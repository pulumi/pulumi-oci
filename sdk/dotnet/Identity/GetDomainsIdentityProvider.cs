// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetDomainsIdentityProvider
    {
        /// <summary>
        /// This data source provides details about a specific Identity Provider resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get an Identity Provider
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testIdentityProvider = Oci.Identity.GetDomainsIdentityProvider.Invoke(new()
        ///     {
        ///         IdcsEndpoint = data.Oci_identity_domain.Test_domain.Url,
        ///         IdentityProviderId = oci_identity_identity_provider.Test_identity_provider.Id,
        ///         AttributeSets = new[] {},
        ///         Attributes = "",
        ///         Authorization = @var.Identity_provider_authorization,
        ///         ResourceTypeSchemaVersion = @var.Identity_provider_resource_type_schema_version,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDomainsIdentityProviderResult> InvokeAsync(GetDomainsIdentityProviderArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDomainsIdentityProviderResult>("oci:Identity/getDomainsIdentityProvider:getDomainsIdentityProvider", args ?? new GetDomainsIdentityProviderArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Identity Provider resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get an Identity Provider
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testIdentityProvider = Oci.Identity.GetDomainsIdentityProvider.Invoke(new()
        ///     {
        ///         IdcsEndpoint = data.Oci_identity_domain.Test_domain.Url,
        ///         IdentityProviderId = oci_identity_identity_provider.Test_identity_provider.Id,
        ///         AttributeSets = new[] {},
        ///         Attributes = "",
        ///         Authorization = @var.Identity_provider_authorization,
        ///         ResourceTypeSchemaVersion = @var.Identity_provider_resource_type_schema_version,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDomainsIdentityProviderResult> Invoke(GetDomainsIdentityProviderInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDomainsIdentityProviderResult>("oci:Identity/getDomainsIdentityProvider:getDomainsIdentityProvider", args ?? new GetDomainsIdentityProviderInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDomainsIdentityProviderArgs : global::Pulumi.InvokeArgs
    {
        [Input("attributeSets")]
        private List<string>? _attributeSets;

        /// <summary>
        /// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
        /// </summary>
        public List<string> AttributeSets
        {
            get => _attributeSets ?? (_attributeSets = new List<string>());
            set => _attributeSets = value;
        }

        /// <summary>
        /// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
        /// </summary>
        [Input("attributes")]
        public string? Attributes { get; set; }

        /// <summary>
        /// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
        /// </summary>
        [Input("authorization")]
        public string? Authorization { get; set; }

        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        [Input("idcsEndpoint", required: true)]
        public string IdcsEndpoint { get; set; } = null!;

        /// <summary>
        /// ID of the resource
        /// </summary>
        [Input("identityProviderId", required: true)]
        public string IdentityProviderId { get; set; } = null!;

        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public string? ResourceTypeSchemaVersion { get; set; }

        public GetDomainsIdentityProviderArgs()
        {
        }
        public static new GetDomainsIdentityProviderArgs Empty => new GetDomainsIdentityProviderArgs();
    }

    public sealed class GetDomainsIdentityProviderInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("attributeSets")]
        private InputList<string>? _attributeSets;

        /// <summary>
        /// A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
        /// </summary>
        public InputList<string> AttributeSets
        {
            get => _attributeSets ?? (_attributeSets = new InputList<string>());
            set => _attributeSets = value;
        }

        /// <summary>
        /// A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
        /// </summary>
        [Input("attributes")]
        public Input<string>? Attributes { get; set; }

        /// <summary>
        /// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
        /// </summary>
        [Input("authorization")]
        public Input<string>? Authorization { get; set; }

        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        [Input("idcsEndpoint", required: true)]
        public Input<string> IdcsEndpoint { get; set; } = null!;

        /// <summary>
        /// ID of the resource
        /// </summary>
        [Input("identityProviderId", required: true)]
        public Input<string> IdentityProviderId { get; set; } = null!;

        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public Input<string>? ResourceTypeSchemaVersion { get; set; }

        public GetDomainsIdentityProviderInvokeArgs()
        {
        }
        public static new GetDomainsIdentityProviderInvokeArgs Empty => new GetDomainsIdentityProviderInvokeArgs();
    }


    [OutputType]
    public sealed class GetDomainsIdentityProviderResult
    {
        /// <summary>
        /// Assertion attribute name.
        /// </summary>
        public readonly string AssertionAttribute;
        public readonly ImmutableArray<string> AttributeSets;
        public readonly string? Attributes;
        /// <summary>
        /// HTTP binding to use for authentication requests.
        /// </summary>
        public readonly string AuthnRequestBinding;
        public readonly string? Authorization;
        /// <summary>
        /// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string CompartmentOcid;
        /// <summary>
        /// Correlation policy
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsIdentityProviderCorrelationPolicyResult> CorrelationPolicies;
        /// <summary>
        /// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
        /// </summary>
        public readonly bool DeleteInProgress;
        /// <summary>
        /// Description
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string DomainOcid;
        /// <summary>
        /// Set to true to indicate Partner enabled.
        /// </summary>
        public readonly bool Enabled;
        /// <summary>
        /// Encryption certificate
        /// </summary>
        public readonly string EncryptionCertificate;
        /// <summary>
        /// An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer's tenant.
        /// </summary>
        public readonly string ExternalId;
        /// <summary>
        /// Identity Provider Icon URL.
        /// </summary>
        public readonly string IconUrl;
        /// <summary>
        /// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The User or App who created the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsIdentityProviderIdcsCreatedByResult> IdcsCreatedBies;
        public readonly string IdcsEndpoint;
        /// <summary>
        /// The User or App who modified the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsIdentityProviderIdcsLastModifiedByResult> IdcsLastModifiedBies;
        /// <summary>
        /// The release number when the resource was upgraded.
        /// </summary>
        public readonly string IdcsLastUpgradedInRelease;
        /// <summary>
        /// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
        /// </summary>
        public readonly ImmutableArray<string> IdcsPreventedOperations;
        public readonly string IdentityProviderId;
        /// <summary>
        /// Identity Provider SSO URL
        /// </summary>
        public readonly string IdpSsoUrl;
        /// <summary>
        /// Set to true to include the signing certificate in the signature.
        /// </summary>
        public readonly bool IncludeSigningCertInSignature;
        /// <summary>
        /// Refers to every group of which a JIT-provisioned User should be a member.  Just-in-Time user-provisioning applies this static list when jitUserProvGroupStaticListEnabled:true.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsIdentityProviderJitUserProvAssignedGroupResult> JitUserProvAssignedGroups;
        /// <summary>
        /// Set to true to indicate JIT User Creation is enabled
        /// </summary>
        public readonly bool JitUserProvAttributeUpdateEnabled;
        /// <summary>
        /// Assertion To User Mapping
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsIdentityProviderJitUserProvAttributeResult> JitUserProvAttributes;
        /// <summary>
        /// Set to true to indicate JIT User Creation is enabled
        /// </summary>
        public readonly bool JitUserProvCreateUserEnabled;
        /// <summary>
        /// Set to true to indicate JIT User Provisioning is enabled
        /// </summary>
        public readonly bool JitUserProvEnabled;
        /// <summary>
        /// Set to true to indicate JIT User Provisioning Groups should be assigned based on assertion attribute
        /// </summary>
        public readonly bool JitUserProvGroupAssertionAttributeEnabled;
        /// <summary>
        /// The default value is 'Overwrite', which tells Just-In-Time user-provisioning to replace any current group-assignments for a User with those assigned by assertions and/or those assigned statically. Specify 'Merge' if you want Just-In-Time user-provisioning to combine its group-assignments with those the user already has.
        /// </summary>
        public readonly string JitUserProvGroupAssignmentMethod;
        /// <summary>
        /// Property to indicate the mode of group mapping
        /// </summary>
        public readonly string JitUserProvGroupMappingMode;
        /// <summary>
        /// The list of mappings between the Identity Domain Group and the IDP group.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsIdentityProviderJitUserProvGroupMappingResult> JitUserProvGroupMappings;
        /// <summary>
        /// Name of the assertion attribute containing the users groups
        /// </summary>
        public readonly string JitUserProvGroupSamlAttributeName;
        /// <summary>
        /// Set to true to indicate JIT User Provisioning Groups should be assigned from a static list
        /// </summary>
        public readonly bool JitUserProvGroupStaticListEnabled;
        /// <summary>
        /// Set to true to indicate ignoring absence of group while provisioning
        /// </summary>
        public readonly bool JitUserProvIgnoreErrorOnAbsentGroups;
        /// <summary>
        /// HTTP binding to use for logout.
        /// </summary>
        public readonly string LogoutBinding;
        /// <summary>
        /// Set to true to enable logout.
        /// </summary>
        public readonly bool LogoutEnabled;
        /// <summary>
        /// Logout request URL
        /// </summary>
        public readonly string LogoutRequestUrl;
        /// <summary>
        /// Logout response URL
        /// </summary>
        public readonly string LogoutResponseUrl;
        /// <summary>
        /// Metadata
        /// </summary>
        public readonly string Metadata;
        /// <summary>
        /// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsIdentityProviderMetaResult> Metas;
        /// <summary>
        /// Default authentication request name ID format.
        /// </summary>
        public readonly string NameIdFormat;
        /// <summary>
        /// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
        /// </summary>
        public readonly string Ocid;
        /// <summary>
        /// Unique name of the trusted Identity Provider.
        /// </summary>
        public readonly string PartnerName;
        /// <summary>
        /// Provider ID
        /// </summary>
        public readonly string PartnerProviderId;
        /// <summary>
        /// SAML SP authentication type.
        /// </summary>
        public readonly ImmutableArray<string> RequestedAuthenticationContexts;
        /// <summary>
        /// This SP requires requests SAML IdP to enforce re-authentication.
        /// </summary>
        public readonly bool RequireForceAuthn;
        /// <summary>
        /// SAML SP must accept encrypted assertion only.
        /// </summary>
        public readonly bool RequiresEncryptedAssertion;
        public readonly string? ResourceTypeSchemaVersion;
        /// <summary>
        /// SAML SP HoK Enabled.
        /// </summary>
        public readonly bool SamlHoKrequired;
        /// <summary>
        /// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
        /// </summary>
        public readonly ImmutableArray<string> Schemas;
        /// <summary>
        /// The serviceInstanceIdentifier of the App that hosts this IdP. This value will match the opcServiceInstanceGUID of any service-instance that the IdP represents.
        /// </summary>
        public readonly string ServiceInstanceIdentifier;
        /// <summary>
        /// Set to true to indicate whether to show IdP in login page or not.
        /// </summary>
        public readonly bool ShownOnLoginPage;
        /// <summary>
        /// Signature hash algorithm.
        /// </summary>
        public readonly string SignatureHashAlgorithm;
        /// <summary>
        /// Signing certificate
        /// </summary>
        public readonly string SigningCertificate;
        /// <summary>
        /// Succinct ID
        /// </summary>
        public readonly string SuccinctId;
        /// <summary>
        /// A list of tags on this resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsIdentityProviderTagResult> Tags;
        /// <summary>
        /// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string TenancyOcid;
        /// <summary>
        /// The alternate Provider ID to be used as the Oracle Identity Cloud Service providerID (instead of the one in SamlSettings) when interacting with this IdP.
        /// </summary>
        public readonly string TenantProviderId;
        /// <summary>
        /// Identity Provider Type
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// Social Identity Provider Extension Schema
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProviderResult> UrnietfparamsscimschemasoracleidcsextensionsocialIdentityProviders;
        /// <summary>
        /// X509 Identity Provider Extension Schema
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionx509identityProviderResult> Urnietfparamsscimschemasoracleidcsextensionx509identityProviders;
        /// <summary>
        /// User mapping method.
        /// </summary>
        public readonly string UserMappingMethod;
        /// <summary>
        /// This property specifies the userstore attribute value that must match the incoming assertion attribute value or the incoming nameid attribute value in order to identify the user during SSO.&lt;br&gt;You can construct the userMappingStoreAttribute value by specifying attributes from the Oracle Identity Cloud Service Core Users schema. For examples of how to construct the userMappingStoreAttribute value, see the &lt;b&gt;Example of a Request Body&lt;/b&gt; section of the Examples tab for the &lt;a href='./op-admin-v1-identityproviders-post.html'&gt;POST&lt;/a&gt; and &lt;a href='./op-admin-v1-identityproviders-id-put.html'&gt;PUT&lt;/a&gt; methods of the /IdentityProviders endpoint.
        /// </summary>
        public readonly string UserMappingStoreAttribute;

        [OutputConstructor]
        private GetDomainsIdentityProviderResult(
            string assertionAttribute,

            ImmutableArray<string> attributeSets,

            string? attributes,

            string authnRequestBinding,

            string? authorization,

            string compartmentOcid,

            ImmutableArray<Outputs.GetDomainsIdentityProviderCorrelationPolicyResult> correlationPolicies,

            bool deleteInProgress,

            string description,

            string domainOcid,

            bool enabled,

            string encryptionCertificate,

            string externalId,

            string iconUrl,

            string id,

            ImmutableArray<Outputs.GetDomainsIdentityProviderIdcsCreatedByResult> idcsCreatedBies,

            string idcsEndpoint,

            ImmutableArray<Outputs.GetDomainsIdentityProviderIdcsLastModifiedByResult> idcsLastModifiedBies,

            string idcsLastUpgradedInRelease,

            ImmutableArray<string> idcsPreventedOperations,

            string identityProviderId,

            string idpSsoUrl,

            bool includeSigningCertInSignature,

            ImmutableArray<Outputs.GetDomainsIdentityProviderJitUserProvAssignedGroupResult> jitUserProvAssignedGroups,

            bool jitUserProvAttributeUpdateEnabled,

            ImmutableArray<Outputs.GetDomainsIdentityProviderJitUserProvAttributeResult> jitUserProvAttributes,

            bool jitUserProvCreateUserEnabled,

            bool jitUserProvEnabled,

            bool jitUserProvGroupAssertionAttributeEnabled,

            string jitUserProvGroupAssignmentMethod,

            string jitUserProvGroupMappingMode,

            ImmutableArray<Outputs.GetDomainsIdentityProviderJitUserProvGroupMappingResult> jitUserProvGroupMappings,

            string jitUserProvGroupSamlAttributeName,

            bool jitUserProvGroupStaticListEnabled,

            bool jitUserProvIgnoreErrorOnAbsentGroups,

            string logoutBinding,

            bool logoutEnabled,

            string logoutRequestUrl,

            string logoutResponseUrl,

            string metadata,

            ImmutableArray<Outputs.GetDomainsIdentityProviderMetaResult> metas,

            string nameIdFormat,

            string ocid,

            string partnerName,

            string partnerProviderId,

            ImmutableArray<string> requestedAuthenticationContexts,

            bool requireForceAuthn,

            bool requiresEncryptedAssertion,

            string? resourceTypeSchemaVersion,

            bool samlHoKrequired,

            ImmutableArray<string> schemas,

            string serviceInstanceIdentifier,

            bool shownOnLoginPage,

            string signatureHashAlgorithm,

            string signingCertificate,

            string succinctId,

            ImmutableArray<Outputs.GetDomainsIdentityProviderTagResult> tags,

            string tenancyOcid,

            string tenantProviderId,

            string type,

            ImmutableArray<Outputs.GetDomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProviderResult> urnietfparamsscimschemasoracleidcsextensionsocialIdentityProviders,

            ImmutableArray<Outputs.GetDomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionx509identityProviderResult> urnietfparamsscimschemasoracleidcsextensionx509identityProviders,

            string userMappingMethod,

            string userMappingStoreAttribute)
        {
            AssertionAttribute = assertionAttribute;
            AttributeSets = attributeSets;
            Attributes = attributes;
            AuthnRequestBinding = authnRequestBinding;
            Authorization = authorization;
            CompartmentOcid = compartmentOcid;
            CorrelationPolicies = correlationPolicies;
            DeleteInProgress = deleteInProgress;
            Description = description;
            DomainOcid = domainOcid;
            Enabled = enabled;
            EncryptionCertificate = encryptionCertificate;
            ExternalId = externalId;
            IconUrl = iconUrl;
            Id = id;
            IdcsCreatedBies = idcsCreatedBies;
            IdcsEndpoint = idcsEndpoint;
            IdcsLastModifiedBies = idcsLastModifiedBies;
            IdcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            IdcsPreventedOperations = idcsPreventedOperations;
            IdentityProviderId = identityProviderId;
            IdpSsoUrl = idpSsoUrl;
            IncludeSigningCertInSignature = includeSigningCertInSignature;
            JitUserProvAssignedGroups = jitUserProvAssignedGroups;
            JitUserProvAttributeUpdateEnabled = jitUserProvAttributeUpdateEnabled;
            JitUserProvAttributes = jitUserProvAttributes;
            JitUserProvCreateUserEnabled = jitUserProvCreateUserEnabled;
            JitUserProvEnabled = jitUserProvEnabled;
            JitUserProvGroupAssertionAttributeEnabled = jitUserProvGroupAssertionAttributeEnabled;
            JitUserProvGroupAssignmentMethod = jitUserProvGroupAssignmentMethod;
            JitUserProvGroupMappingMode = jitUserProvGroupMappingMode;
            JitUserProvGroupMappings = jitUserProvGroupMappings;
            JitUserProvGroupSamlAttributeName = jitUserProvGroupSamlAttributeName;
            JitUserProvGroupStaticListEnabled = jitUserProvGroupStaticListEnabled;
            JitUserProvIgnoreErrorOnAbsentGroups = jitUserProvIgnoreErrorOnAbsentGroups;
            LogoutBinding = logoutBinding;
            LogoutEnabled = logoutEnabled;
            LogoutRequestUrl = logoutRequestUrl;
            LogoutResponseUrl = logoutResponseUrl;
            Metadata = metadata;
            Metas = metas;
            NameIdFormat = nameIdFormat;
            Ocid = ocid;
            PartnerName = partnerName;
            PartnerProviderId = partnerProviderId;
            RequestedAuthenticationContexts = requestedAuthenticationContexts;
            RequireForceAuthn = requireForceAuthn;
            RequiresEncryptedAssertion = requiresEncryptedAssertion;
            ResourceTypeSchemaVersion = resourceTypeSchemaVersion;
            SamlHoKrequired = samlHoKrequired;
            Schemas = schemas;
            ServiceInstanceIdentifier = serviceInstanceIdentifier;
            ShownOnLoginPage = shownOnLoginPage;
            SignatureHashAlgorithm = signatureHashAlgorithm;
            SigningCertificate = signingCertificate;
            SuccinctId = succinctId;
            Tags = tags;
            TenancyOcid = tenancyOcid;
            TenantProviderId = tenantProviderId;
            Type = type;
            UrnietfparamsscimschemasoracleidcsextensionsocialIdentityProviders = urnietfparamsscimschemasoracleidcsextensionsocialIdentityProviders;
            Urnietfparamsscimschemasoracleidcsextensionx509identityProviders = urnietfparamsscimschemasoracleidcsextensionx509identityProviders;
            UserMappingMethod = userMappingMethod;
            UserMappingStoreAttribute = userMappingStoreAttribute;
        }
    }
}