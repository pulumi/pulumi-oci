// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetDomainsAuthenticationFactorSetting
    {
        /// <summary>
        /// This data source provides details about a specific Authentication Factor Setting resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get Authentication Factor Settings
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAuthenticationFactorSetting = Oci.Identity.GetDomainsAuthenticationFactorSetting.Invoke(new()
        ///     {
        ///         AuthenticationFactorSettingId = testAuthenticationFactorSettingOciIdentityDomainsAuthenticationFactorSetting.Id,
        ///         IdcsEndpoint = testDomain.Url,
        ///         AttributeSets = new() { },
        ///         Attributes = "",
        ///         Authorization = authenticationFactorSettingAuthorization,
        ///         ResourceTypeSchemaVersion = authenticationFactorSettingResourceTypeSchemaVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDomainsAuthenticationFactorSettingResult> InvokeAsync(GetDomainsAuthenticationFactorSettingArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDomainsAuthenticationFactorSettingResult>("oci:Identity/getDomainsAuthenticationFactorSetting:getDomainsAuthenticationFactorSetting", args ?? new GetDomainsAuthenticationFactorSettingArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Authentication Factor Setting resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get Authentication Factor Settings
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAuthenticationFactorSetting = Oci.Identity.GetDomainsAuthenticationFactorSetting.Invoke(new()
        ///     {
        ///         AuthenticationFactorSettingId = testAuthenticationFactorSettingOciIdentityDomainsAuthenticationFactorSetting.Id,
        ///         IdcsEndpoint = testDomain.Url,
        ///         AttributeSets = new() { },
        ///         Attributes = "",
        ///         Authorization = authenticationFactorSettingAuthorization,
        ///         ResourceTypeSchemaVersion = authenticationFactorSettingResourceTypeSchemaVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDomainsAuthenticationFactorSettingResult> Invoke(GetDomainsAuthenticationFactorSettingInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDomainsAuthenticationFactorSettingResult>("oci:Identity/getDomainsAuthenticationFactorSetting:getDomainsAuthenticationFactorSetting", args ?? new GetDomainsAuthenticationFactorSettingInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Authentication Factor Setting resource in Oracle Cloud Infrastructure Identity Domains service.
        /// 
        /// Get Authentication Factor Settings
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAuthenticationFactorSetting = Oci.Identity.GetDomainsAuthenticationFactorSetting.Invoke(new()
        ///     {
        ///         AuthenticationFactorSettingId = testAuthenticationFactorSettingOciIdentityDomainsAuthenticationFactorSetting.Id,
        ///         IdcsEndpoint = testDomain.Url,
        ///         AttributeSets = new() { },
        ///         Attributes = "",
        ///         Authorization = authenticationFactorSettingAuthorization,
        ///         ResourceTypeSchemaVersion = authenticationFactorSettingResourceTypeSchemaVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDomainsAuthenticationFactorSettingResult> Invoke(GetDomainsAuthenticationFactorSettingInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDomainsAuthenticationFactorSettingResult>("oci:Identity/getDomainsAuthenticationFactorSetting:getDomainsAuthenticationFactorSetting", args ?? new GetDomainsAuthenticationFactorSettingInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDomainsAuthenticationFactorSettingArgs : global::Pulumi.InvokeArgs
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
        /// ID of the resource
        /// </summary>
        [Input("authenticationFactorSettingId")]
        public string? AuthenticationFactorSettingId { get; set; }

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
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public string? ResourceTypeSchemaVersion { get; set; }

        public GetDomainsAuthenticationFactorSettingArgs()
        {
        }
        public static new GetDomainsAuthenticationFactorSettingArgs Empty => new GetDomainsAuthenticationFactorSettingArgs();
    }

    public sealed class GetDomainsAuthenticationFactorSettingInvokeArgs : global::Pulumi.InvokeArgs
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
        /// ID of the resource
        /// </summary>
        [Input("authenticationFactorSettingId")]
        public Input<string>? AuthenticationFactorSettingId { get; set; }

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
        /// An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
        /// </summary>
        [Input("resourceTypeSchemaVersion")]
        public Input<string>? ResourceTypeSchemaVersion { get; set; }

        public GetDomainsAuthenticationFactorSettingInvokeArgs()
        {
        }
        public static new GetDomainsAuthenticationFactorSettingInvokeArgs Empty => new GetDomainsAuthenticationFactorSettingInvokeArgs();
    }


    [OutputType]
    public sealed class GetDomainsAuthenticationFactorSettingResult
    {
        public readonly ImmutableArray<string> AttributeSets;
        public readonly string? Attributes;
        public readonly string? AuthenticationFactorSettingId;
        public readonly string? Authorization;
        /// <summary>
        /// If true, indicates that email will not be enrolled as a MFA factor automatically if it a account recovery factor
        /// </summary>
        public readonly bool AutoEnrollEmailFactorDisabled;
        /// <summary>
        /// If true, indicates that Bypass Code is enabled for authentication
        /// </summary>
        public readonly bool BypassCodeEnabled;
        /// <summary>
        /// Settings related to the bypass code, such as bypass code length, bypass code expiry, max active bypass codes, and so on
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingBypassCodeSettingResult> BypassCodeSettings;
        /// <summary>
        /// Settings related to compliance, Personal Identification Number (PIN) policy, and so on
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingClientAppSettingResult> ClientAppSettings;
        /// <summary>
        /// Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string CompartmentOcid;
        /// <summary>
        /// Compliance Policy that defines actions to be taken when a condition is violated
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingCompliancePolicyResult> CompliancePolicies;
        /// <summary>
        /// A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
        /// </summary>
        public readonly bool DeleteInProgress;
        /// <summary>
        /// Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string DomainOcid;
        /// <summary>
        /// If true, indicates that the EMAIL channel is enabled for authentication
        /// </summary>
        public readonly bool EmailEnabled;
        /// <summary>
        /// Settings related to Email Factor, such as enabled email magic link factor, custom url for Email Link
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingEmailSettingResult> EmailSettings;
        /// <summary>
        /// Settings that describe the set of restrictions that the system should apply to devices and trusted endpoints of a user
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingEndpointRestrictionResult> EndpointRestrictions;
        /// <summary>
        /// If true, indicates that the Fido Authenticator channels are enabled for authentication
        /// </summary>
        public readonly bool FidoAuthenticatorEnabled;
        /// <summary>
        /// If true, indicates that 'Show backup factor(s)' button will be hidden during authentication
        /// </summary>
        public readonly bool HideBackupFactorEnabled;
        /// <summary>
        /// Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The User or App who created the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingIdcsCreatedByResult> IdcsCreatedBies;
        public readonly string IdcsEndpoint;
        /// <summary>
        /// The User or App who modified the Resource
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingIdcsLastModifiedByResult> IdcsLastModifiedBies;
        /// <summary>
        /// The release number when the resource was upgraded.
        /// </summary>
        public readonly string IdcsLastUpgradedInRelease;
        /// <summary>
        /// Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
        /// </summary>
        public readonly ImmutableArray<string> IdcsPreventedOperations;
        /// <summary>
        /// Settings related to the use of a user's profile details from the identity store
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingIdentityStoreSettingResult> IdentityStoreSettings;
        /// <summary>
        /// A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingMetaResult> Metas;
        /// <summary>
        /// Specifies the category of people for whom Multi-Factor Authentication is enabled. This is a readOnly attribute which reflects the value of mfaEnabledCategory attribute in SsoSettings
        /// </summary>
        public readonly string MfaEnabledCategory;
        /// <summary>
        /// Specifies if Multi-Factor Authentication enrollment is mandatory or optional for a user
        /// </summary>
        public readonly string MfaEnrollmentType;
        /// <summary>
        /// Settings related to the Mobile App Notification channel, such as pull
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingNotificationSettingResult> NotificationSettings;
        /// <summary>
        /// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
        /// </summary>
        public readonly string Ocid;
        /// <summary>
        /// If true, indicates that the phone (PHONE_CALL) channel is enabled for authentication
        /// </summary>
        public readonly bool PhoneCallEnabled;
        /// <summary>
        /// If true, indicates that the Mobile App Push Notification channel is enabled for authentication
        /// </summary>
        public readonly bool PushEnabled;
        public readonly string? ResourceTypeSchemaVersion;
        /// <summary>
        /// REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \"enterprise\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
        /// </summary>
        public readonly ImmutableArray<string> Schemas;
        /// <summary>
        /// If true, indicates that Security Questions are enabled for authentication
        /// </summary>
        public readonly bool SecurityQuestionsEnabled;
        /// <summary>
        /// If true, indicates that the Short Message Service (SMS) channel is enabled for authentication
        /// </summary>
        public readonly bool SmsEnabled;
        /// <summary>
        /// A list of tags on this resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingTagResult> Tags;
        /// <summary>
        /// Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
        /// </summary>
        public readonly string TenancyOcid;
        /// <summary>
        /// Settings related to third-party factor
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingThirdPartyFactorResult> ThirdPartyFactors;
        /// <summary>
        /// If true, indicates that the Mobile App One Time Passcode channel is enabled for authentication
        /// </summary>
        public readonly bool TotpEnabled;
        /// <summary>
        /// Settings related to Time-Based One-Time Passcodes (TOTP), such as hashing algo, totp time step, passcode length, and so on
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingTotpSettingResult> TotpSettings;
        /// <summary>
        /// This extension defines attributes used to manage Multi-Factor Authentication settings of fido authentication
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionfidoAuthenticationFactorSettingResult> UrnietfparamsscimschemasoracleidcsextensionfidoAuthenticationFactorSettings;
        /// <summary>
        /// This extension defines attributes used to manage Multi-Factor Authentication settings of third party provider
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettingResult> UrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettings;
        /// <summary>
        /// Factors for which enrollment should be blocked for End User
        /// </summary>
        public readonly ImmutableArray<string> UserEnrollmentDisabledFactors;
        /// <summary>
        /// If true, indicates that the Yubico OTP is enabled for authentication
        /// </summary>
        public readonly bool YubicoOtpEnabled;

        [OutputConstructor]
        private GetDomainsAuthenticationFactorSettingResult(
            ImmutableArray<string> attributeSets,

            string? attributes,

            string? authenticationFactorSettingId,

            string? authorization,

            bool autoEnrollEmailFactorDisabled,

            bool bypassCodeEnabled,

            ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingBypassCodeSettingResult> bypassCodeSettings,

            ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingClientAppSettingResult> clientAppSettings,

            string compartmentOcid,

            ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingCompliancePolicyResult> compliancePolicies,

            bool deleteInProgress,

            string domainOcid,

            bool emailEnabled,

            ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingEmailSettingResult> emailSettings,

            ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingEndpointRestrictionResult> endpointRestrictions,

            bool fidoAuthenticatorEnabled,

            bool hideBackupFactorEnabled,

            string id,

            ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingIdcsCreatedByResult> idcsCreatedBies,

            string idcsEndpoint,

            ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingIdcsLastModifiedByResult> idcsLastModifiedBies,

            string idcsLastUpgradedInRelease,

            ImmutableArray<string> idcsPreventedOperations,

            ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingIdentityStoreSettingResult> identityStoreSettings,

            ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingMetaResult> metas,

            string mfaEnabledCategory,

            string mfaEnrollmentType,

            ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingNotificationSettingResult> notificationSettings,

            string ocid,

            bool phoneCallEnabled,

            bool pushEnabled,

            string? resourceTypeSchemaVersion,

            ImmutableArray<string> schemas,

            bool securityQuestionsEnabled,

            bool smsEnabled,

            ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingTagResult> tags,

            string tenancyOcid,

            ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingThirdPartyFactorResult> thirdPartyFactors,

            bool totpEnabled,

            ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingTotpSettingResult> totpSettings,

            ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionfidoAuthenticationFactorSettingResult> urnietfparamsscimschemasoracleidcsextensionfidoAuthenticationFactorSettings,

            ImmutableArray<Outputs.GetDomainsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettingResult> urnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettings,

            ImmutableArray<string> userEnrollmentDisabledFactors,

            bool yubicoOtpEnabled)
        {
            AttributeSets = attributeSets;
            Attributes = attributes;
            AuthenticationFactorSettingId = authenticationFactorSettingId;
            Authorization = authorization;
            AutoEnrollEmailFactorDisabled = autoEnrollEmailFactorDisabled;
            BypassCodeEnabled = bypassCodeEnabled;
            BypassCodeSettings = bypassCodeSettings;
            ClientAppSettings = clientAppSettings;
            CompartmentOcid = compartmentOcid;
            CompliancePolicies = compliancePolicies;
            DeleteInProgress = deleteInProgress;
            DomainOcid = domainOcid;
            EmailEnabled = emailEnabled;
            EmailSettings = emailSettings;
            EndpointRestrictions = endpointRestrictions;
            FidoAuthenticatorEnabled = fidoAuthenticatorEnabled;
            HideBackupFactorEnabled = hideBackupFactorEnabled;
            Id = id;
            IdcsCreatedBies = idcsCreatedBies;
            IdcsEndpoint = idcsEndpoint;
            IdcsLastModifiedBies = idcsLastModifiedBies;
            IdcsLastUpgradedInRelease = idcsLastUpgradedInRelease;
            IdcsPreventedOperations = idcsPreventedOperations;
            IdentityStoreSettings = identityStoreSettings;
            Metas = metas;
            MfaEnabledCategory = mfaEnabledCategory;
            MfaEnrollmentType = mfaEnrollmentType;
            NotificationSettings = notificationSettings;
            Ocid = ocid;
            PhoneCallEnabled = phoneCallEnabled;
            PushEnabled = pushEnabled;
            ResourceTypeSchemaVersion = resourceTypeSchemaVersion;
            Schemas = schemas;
            SecurityQuestionsEnabled = securityQuestionsEnabled;
            SmsEnabled = smsEnabled;
            Tags = tags;
            TenancyOcid = tenancyOcid;
            ThirdPartyFactors = thirdPartyFactors;
            TotpEnabled = totpEnabled;
            TotpSettings = totpSettings;
            UrnietfparamsscimschemasoracleidcsextensionfidoAuthenticationFactorSettings = urnietfparamsscimschemasoracleidcsextensionfidoAuthenticationFactorSettings;
            UrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettings = urnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettings;
            UserEnrollmentDisabledFactors = userEnrollmentDisabledFactors;
            YubicoOtpEnabled = yubicoOtpEnabled;
        }
    }
}
