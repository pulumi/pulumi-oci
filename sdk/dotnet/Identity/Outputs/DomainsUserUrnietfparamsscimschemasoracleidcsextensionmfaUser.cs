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
    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUser
    {
        /// <summary>
        /// (Updatable) A list of bypass codes that belongs to the user.
        /// 
        /// **Added In:** 18.3.6
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [value]
        /// * multiValued: true
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public readonly ImmutableArray<Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserBypassCode> BypassCodes;
        /// <summary>
        /// (Updatable) A list of devices enrolled by the user.
        /// 
        /// **Added In:** 18.3.6
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [value]
        /// * multiValued: true
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public readonly ImmutableArray<Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserDevice> Devices;
        /// <summary>
        /// (Updatable) The number of incorrect multi factor authentication sign in attempts made by this user. The user is  locked if this reaches the threshold specified in the maxIncorrectAttempts attribute in AuthenticationFactorSettings.
        /// 
        /// **Added In:** 18.3.6
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * idcsRequiresWriteForAccessFlows: true
        /// * idcsRequiresImmediateReadAfterWriteForAccessFlows: true
        /// * required: false
        /// * returned: default
        /// * type: integer
        /// * uniqueness: none
        /// </summary>
        public readonly int? LoginAttempts;
        /// <summary>
        /// (Updatable) The date when the user enrolled in multi factor authentication. This will be set to null, when the user resets their factors.
        /// 
        /// **Added In:** 18.3.6
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: dateTime
        /// * uniqueness: none
        /// </summary>
        public readonly string? MfaEnabledOn;
        /// <summary>
        /// (Updatable) User MFA Ignored Apps Identifiers
        /// 
        /// **Added In:** 19.2.1
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: true
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly ImmutableArray<string> MfaIgnoredApps;
        /// <summary>
        /// (Updatable) The user opted for MFA.
        /// 
        /// **Added In:** 18.3.6
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * idcsRequiresWriteForAccessFlows: true
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? MfaStatus;
        /// <summary>
        /// (Updatable) The preferred authentication factor type.
        /// 
        /// **Added In:** 18.3.6
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
        public readonly string? PreferredAuthenticationFactor;
        /// <summary>
        /// (Updatable) The preferred authentication method.
        /// 
        /// **Added In:** 2009232244
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
        public readonly string? PreferredAuthenticationMethod;
        /// <summary>
        /// (Updatable) The user's preferred device.
        /// 
        /// **Added In:** 18.3.6
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public readonly Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserPreferredDevice? PreferredDevice;
        /// <summary>
        /// (Updatable) The preferred third-party vendor name.
        /// 
        /// **Added In:** 19.2.1
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
        public readonly string? PreferredThirdPartyVendor;
        /// <summary>
        /// (Updatable) A list of trusted User Agents owned by this user. Multi-Factored Authentication uses Trusted User Agents to authenticate users.  A User Agent is software application that a user uses to issue requests. For example, a User Agent could be a particular browser (possibly one of several executing on a desktop or laptop) or a particular mobile application (again, oneof several executing on a particular mobile device). A User Agent is trusted once the Multi-Factor Authentication has verified it in some way.
        /// 
        /// **Added In:** 18.3.6
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [value]
        /// * multiValued: true
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public readonly ImmutableArray<Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgent> TrustedUserAgents;

        [OutputConstructor]
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUser(
            ImmutableArray<Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserBypassCode> bypassCodes,

            ImmutableArray<Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserDevice> devices,

            int? loginAttempts,

            string? mfaEnabledOn,

            ImmutableArray<string> mfaIgnoredApps,

            string? mfaStatus,

            string? preferredAuthenticationFactor,

            string? preferredAuthenticationMethod,

            Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserPreferredDevice? preferredDevice,

            string? preferredThirdPartyVendor,

            ImmutableArray<Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgent> trustedUserAgents)
        {
            BypassCodes = bypassCodes;
            Devices = devices;
            LoginAttempts = loginAttempts;
            MfaEnabledOn = mfaEnabledOn;
            MfaIgnoredApps = mfaIgnoredApps;
            MfaStatus = mfaStatus;
            PreferredAuthenticationFactor = preferredAuthenticationFactor;
            PreferredAuthenticationMethod = preferredAuthenticationMethod;
            PreferredDevice = preferredDevice;
            PreferredThirdPartyVendor = preferredThirdPartyVendor;
            TrustedUserAgents = trustedUserAgents;
        }
    }
}
