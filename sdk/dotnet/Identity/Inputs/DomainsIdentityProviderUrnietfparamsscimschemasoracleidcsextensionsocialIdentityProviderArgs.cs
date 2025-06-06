// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProviderArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Social IDP Access token URL
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("accessTokenUrl")]
        public Input<string>? AccessTokenUrl { get; set; }

        /// <summary>
        /// (Updatable) Whether account linking is enabled
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("accountLinkingEnabled", required: true)]
        public Input<bool> AccountLinkingEnabled { get; set; } = null!;

        [Input("adminScopes")]
        private InputList<string>? _adminScopes;

        /// <summary>
        /// (Updatable) Admin scope to request
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * multiValued: true
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public InputList<string> AdminScopes
        {
            get => _adminScopes ?? (_adminScopes = new InputList<string>());
            set => _adminScopes = value;
        }

        /// <summary>
        /// (Updatable) Social IDP Authorization URL
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("authzUrl")]
        public Input<string>? AuthzUrl { get; set; }

        /// <summary>
        /// (Updatable) Whether social auto redirect is enabled. The IDP policy should be configured with only one Social IDP, and without username/password selected.
        /// 
        /// **Added In:** 2310202314
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("autoRedirectEnabled")]
        public Input<bool>? AutoRedirectEnabled { get; set; }

        /// <summary>
        /// (Updatable) Whether the client credential is contained in payload
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("clientCredentialInPayload")]
        public Input<bool>? ClientCredentialInPayload { get; set; }

        /// <summary>
        /// (Updatable) Social IDP allowed clock skew time
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: integer
        /// * uniqueness: none
        /// </summary>
        [Input("clockSkewInSeconds")]
        public Input<int>? ClockSkewInSeconds { get; set; }

        /// <summary>
        /// (Updatable) Social IDP Client Application Client ID
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("consumerKey", required: true)]
        public Input<string> ConsumerKey { get; set; } = null!;

        /// <summary>
        /// (Updatable) Social IDP Client Application Client Secret
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * idcsSensitive: encrypt
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("consumerSecret", required: true)]
        public Input<string> ConsumerSecret { get; set; } = null!;

        /// <summary>
        /// (Updatable) Discovery URL
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("discoveryUrl")]
        public Input<string>? DiscoveryUrl { get; set; }

        /// <summary>
        /// (Updatable) Id attribute used for account linking
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("idAttribute")]
        public Input<string>? IdAttribute { get; set; }

        [Input("jitProvAssignedGroups")]
        private InputList<Inputs.DomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProviderJitProvAssignedGroupArgs>? _jitProvAssignedGroups;

        /// <summary>
        /// (Updatable) Lists the groups each social JIT-provisioned user is a member. Just-in-Time user-provisioning applies this static list when jitProvGroupStaticListEnabled:true.
        /// 
        /// **Added In:** 2310202314
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [value]
        /// * idcsSearchable: false
        /// * multiValued: true
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public InputList<Inputs.DomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProviderJitProvAssignedGroupArgs> JitProvAssignedGroups
        {
            get => _jitProvAssignedGroups ?? (_jitProvAssignedGroups = new InputList<Inputs.DomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProviderJitProvAssignedGroupArgs>());
            set => _jitProvAssignedGroups = value;
        }

        /// <summary>
        /// (Updatable) Set to true to indicate Social JIT User Provisioning Groups should be assigned from a static list
        /// 
        /// **Added In:** 2310202314
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("jitProvGroupStaticListEnabled")]
        public Input<bool>? JitProvGroupStaticListEnabled { get; set; }

        /// <summary>
        /// (Updatable) Social IDP User profile URL
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("profileUrl")]
        public Input<string>? ProfileUrl { get; set; }

        /// <summary>
        /// (Updatable) redirect URL for social idp
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("redirectUrl")]
        public Input<string>? RedirectUrl { get; set; }

        /// <summary>
        /// (Updatable) Whether registration is enabled
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("registrationEnabled", required: true)]
        public Input<bool> RegistrationEnabled { get; set; } = null!;

        [Input("scopes")]
        private InputList<string>? _scopes;

        /// <summary>
        /// (Updatable) Scope to request
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * multiValued: true
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public InputList<string> Scopes
        {
            get => _scopes ?? (_scopes = new InputList<string>());
            set => _scopes = value;
        }

        /// <summary>
        /// (Updatable) Service Provider Name
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("serviceProviderName", required: true)]
        public Input<string> ServiceProviderName { get; set; } = null!;

        /// <summary>
        /// (Updatable) Whether Social JIT Provisioning is enabled
        /// 
        /// **Added In:** 2307282043
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("socialJitProvisioningEnabled")]
        public Input<bool>? SocialJitProvisioningEnabled { get; set; }

        /// <summary>
        /// (Updatable) Status
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        public DomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProviderArgs()
        {
        }
        public static new DomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProviderArgs Empty => new DomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionsocialIdentityProviderArgs();
    }
}
