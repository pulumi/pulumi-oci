// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetDomainsSocialIdentityProvidersSocialIdentityProviderResult
    {
        /// <summary>
        /// Social IDP Access token URL
        /// </summary>
        public readonly string AccessTokenUrl;
        /// <summary>
        /// Whether account linking is enabled
        /// </summary>
        public readonly bool AccountLinkingEnabled;
        /// <summary>
        /// Admin scope to request
        /// </summary>
        public readonly ImmutableArray<string> AdminScopes;
        /// <summary>
        /// The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
        /// </summary>
        public readonly string Authorization;
        /// <summary>
        /// Social IDP Authorization URL
        /// </summary>
        public readonly string AuthzUrl;
        /// <summary>
        /// Whether social auto redirect is enabled. The IDP policy should be configured with only one Social IDP, and without username/password selected.
        /// </summary>
        public readonly bool AutoRedirectEnabled;
        /// <summary>
        /// Whether the client credential is contained in payload
        /// </summary>
        public readonly bool ClientCredentialInPayload;
        /// <summary>
        /// Social IDP allowed clock skew time
        /// </summary>
        public readonly int ClockSkewInSeconds;
        /// <summary>
        /// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string CompartmentOcid;
        /// <summary>
        /// Social IDP Client Application Client ID
        /// </summary>
        public readonly string ConsumerKey;
        /// <summary>
        /// Social IDP Client Application Client Secret
        /// </summary>
        public readonly string ConsumerSecret;
        /// <summary>
        /// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
        /// </summary>
        public readonly bool DeleteInProgress;
        /// <summary>
        /// Social IDP description
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Discovery URL
        /// </summary>
        public readonly string DiscoveryUrl;
        /// <summary>
        /// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string DomainOcid;
        /// <summary>
        /// Whether the IDP is enabled or not
        /// </summary>
        public readonly bool Enabled;
        /// <summary>
        /// ICON URL for social idp
        /// </summary>
        public readonly string IconUrl;
        /// <summary>
        /// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Id attribute used for account linking
        /// </summary>
        public readonly string IdAttribute;
        /// <summary>
        /// The User or App who created the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsSocialIdentityProvidersSocialIdentityProviderIdcsCreatedByResult> IdcsCreatedBies;
        /// <summary>
        /// The basic endpoint for the identity domain
        /// </summary>
        public readonly string IdcsEndpoint;
        /// <summary>
        /// The User or App who modified the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsSocialIdentityProvidersSocialIdentityProviderIdcsLastModifiedByResult> IdcsLastModifiedBies;
        /// <summary>
        /// The release number when the resource was upgraded.
        /// </summary>
        public readonly string IdcsLastUpgradedInRelease;
        /// <summary>
        /// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
        /// </summary>
        public readonly ImmutableArray<string> IdcsPreventedOperations;
        /// <summary>
        /// Lists the groups each social JIT-provisioned user is a member. Just-in-Time user-provisioning applies this static list when jitProvGroupStaticListEnabled:true.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsSocialIdentityProvidersSocialIdentityProviderJitProvAssignedGroupResult> JitProvAssignedGroups;
        /// <summary>
        /// Set to true to indicate Social JIT User Provisioning Groups should be assigned from a static list
        /// </summary>
        public readonly bool JitProvGroupStaticListEnabled;
        /// <summary>
        /// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsSocialIdentityProvidersSocialIdentityProviderMetaResult> Metas;
        /// <summary>
        /// Social provider name
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
        /// </summary>
        public readonly string Ocid;
        /// <summary>
        /// Social IDP User profile URL
        /// </summary>
        public readonly string ProfileUrl;
        /// <summary>
        /// redirect URL for social idp
        /// </summary>
        public readonly string RedirectUrl;
        /// <summary>
        /// Social IDP Refresh token URL
        /// </summary>
        public readonly string RefreshTokenUrl;
        /// <summary>
        /// Whether registration is enabled
        /// </summary>
        public readonly bool RegistrationEnabled;
        /// <summary>
        /// Relay Param variable for Social IDP
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsSocialIdentityProvidersSocialIdentityProviderRelayIdpParamMappingResult> RelayIdpParamMappings;
        /// <summary>
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        public readonly string ResourceTypeSchemaVersion;
        /// <summary>
        /// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
        /// </summary>
        public readonly ImmutableArray<string> Schemas;
        /// <summary>
        /// Scope to request
        /// </summary>
        public readonly ImmutableArray<string> Scopes;
        /// <summary>
        /// Service Provider Name
        /// </summary>
        public readonly string ServiceProviderName;
        /// <summary>
        /// Whether show on login
        /// </summary>
        public readonly bool ShowOnLogin;
        /// <summary>
        /// Whether Social JIT Provisioning is enabled
        /// </summary>
        public readonly bool SocialJitProvisioningEnabled;
        /// <summary>
        /// Status
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// A list of tags on this resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsSocialIdentityProvidersSocialIdentityProviderTagResult> Tags;
        /// <summary>
        /// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string TenancyOcid;

        [OutputConstructor]
        private GetDomainsSocialIdentityProvidersSocialIdentityProviderResult(
            string accessTokenUrl,

            bool accountLinkingEnabled,

            ImmutableArray<string> adminScopes,

            string authorization,

            string authzUrl,

            bool autoRedirectEnabled,

            bool clientCredentialInPayload,

            int clockSkewInSeconds,

            string compartmentOcid,

            string consumerKey,

            string consumerSecret,

            bool deleteInProgress,

            string description,

            string discoveryUrl,

            string domainOcid,

            bool enabled,

            string iconUrl,

            string id,

            string idAttribute,

            ImmutableArray<Outputs.GetDomainsSocialIdentityProvidersSocialIdentityProviderIdcsCreatedByResult> idcsCreatedBies,

            string idcsEndpoint,

            ImmutableArray<Outputs.GetDomainsSocialIdentityProvidersSocialIdentityProviderIdcsLastModifiedByResult> idcsLastModifiedBies,

            string idcsLastUpgradedInRelease,

            ImmutableArray<string> idcsPreventedOperations,

            ImmutableArray<Outputs.GetDomainsSocialIdentityProvidersSocialIdentityProviderJitProvAssignedGroupResult> jitProvAssignedGroups,

            bool jitProvGroupStaticListEnabled,

            ImmutableArray<Outputs.GetDomainsSocialIdentityProvidersSocialIdentityProviderMetaResult> metas,

            string name,

            string ocid,

            string profileUrl,

            string redirectUrl,

            string refreshTokenUrl,

            bool registrationEnabled,

            ImmutableArray<Outputs.GetDomainsSocialIdentityProvidersSocialIdentityProviderRelayIdpParamMappingResult> relayIdpParamMappings,

            string resourceTypeSchemaVersion,

            ImmutableArray<string> schemas,

            ImmutableArray<string> scopes,

            string serviceProviderName,

            bool showOnLogin,

            bool socialJitProvisioningEnabled,

            string status,

            ImmutableArray<Outputs.GetDomainsSocialIdentityProvidersSocialIdentityProviderTagResult> tags,

            string tenancyOcid)
        {
            AccessTokenUrl = accessTokenUrl;
            AccountLinkingEnabled = accountLinkingEnabled;
            AdminScopes = adminScopes;
            Authorization = authorization;
            AuthzUrl = authzUrl;
            AutoRedirectEnabled = autoRedirectEnabled;
            ClientCredentialInPayload = clientCredentialInPayload;
            ClockSkewInSeconds = clockSkewInSeconds;
            CompartmentOcid = compartmentOcid;
            ConsumerKey = consumerKey;
            ConsumerSecret = consumerSecret;
            DeleteInProgress = deleteInProgress;
            Description = description;
            DiscoveryUrl = discoveryUrl;
            DomainOcid = domainOcid;
            Enabled = enabled;
            IconUrl = iconUrl;
            Id = id;
            IdAttribute = idAttribute;
            IdcsCreatedBies = idcsCreatedBies;
            IdcsEndpoint = idcsEndpoint;
            IdcsLastModifiedBies = idcsLastModifiedBies;
            IdcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            IdcsPreventedOperations = idcsPreventedOperations;
            JitProvAssignedGroups = jitProvAssignedGroups;
            JitProvGroupStaticListEnabled = jitProvGroupStaticListEnabled;
            Metas = metas;
            Name = name;
            Ocid = ocid;
            ProfileUrl = profileUrl;
            RedirectUrl = redirectUrl;
            RefreshTokenUrl = refreshTokenUrl;
            RegistrationEnabled = registrationEnabled;
            RelayIdpParamMappings = relayIdpParamMappings;
            ResourceTypeSchemaVersion = resourceTypeSchemaVersion;
            Schemas = schemas;
            Scopes = scopes;
            ServiceProviderName = serviceProviderName;
            ShowOnLogin = showOnLogin;
            SocialJitProvisioningEnabled = socialJitProvisioningEnabled;
            Status = status;
            Tags = tags;
            TenancyOcid = tenancyOcid;
        }
    }
}
