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
    public sealed class GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserResult
    {
        /// <summary>
        /// A list of bypass codes that belongs to the user.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserBypassCodeResult> BypassCodes;
        /// <summary>
        /// A list of devices enrolled by the user.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserDeviceResult> Devices;
        /// <summary>
        /// The number of failed login attempts. The value is reset to 0 after a successful login.
        /// </summary>
        public readonly int LoginAttempts;
        /// <summary>
        /// The date when the user enrolled in multi factor authentication. This will be set to null, when the user resets their factors.
        /// </summary>
        public readonly string MfaEnabledOn;
        /// <summary>
        /// User MFA Ignored Apps Identifiers
        /// </summary>
        public readonly ImmutableArray<string> MfaIgnoredApps;
        /// <summary>
        /// The user opted for MFA.
        /// </summary>
        public readonly string MfaStatus;
        /// <summary>
        /// The preferred authentication factor type.
        /// </summary>
        public readonly string PreferredAuthenticationFactor;
        /// <summary>
        /// The preferred authentication method.
        /// </summary>
        public readonly string PreferredAuthenticationMethod;
        /// <summary>
        /// The user's preferred device.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserPreferredDeviceResult> PreferredDevices;
        /// <summary>
        /// The preferred third-party vendor name.
        /// </summary>
        public readonly string PreferredThirdPartyVendor;
        /// <summary>
        /// A list of trusted User Agents owned by this user. Multi-Factored Authentication uses Trusted User Agents to authenticate users.  A User Agent is software application that a user uses to issue requests. For example, a User Agent could be a particular browser (possibly one of several executing on a desktop or laptop) or a particular mobile application (again, oneof several executing on a particular mobile device). A User Agent is trusted once the Multi-Factor Authentication has verified it in some way.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgentResult> TrustedUserAgents;

        [OutputConstructor]
        private GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserResult(
            ImmutableArray<Outputs.GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserBypassCodeResult> bypassCodes,

            ImmutableArray<Outputs.GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserDeviceResult> devices,

            int loginAttempts,

            string mfaEnabledOn,

            ImmutableArray<string> mfaIgnoredApps,

            string mfaStatus,

            string preferredAuthenticationFactor,

            string preferredAuthenticationMethod,

            ImmutableArray<Outputs.GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserPreferredDeviceResult> preferredDevices,

            string preferredThirdPartyVendor,

            ImmutableArray<Outputs.GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionmfaUserTrustedUserAgentResult> trustedUserAgents)
        {
            BypassCodes = bypassCodes;
            Devices = devices;
            LoginAttempts = loginAttempts;
            MfaEnabledOn = mfaEnabledOn;
            MfaIgnoredApps = mfaIgnoredApps;
            MfaStatus = mfaStatus;
            PreferredAuthenticationFactor = preferredAuthenticationFactor;
            PreferredAuthenticationMethod = preferredAuthenticationMethod;
            PreferredDevices = preferredDevices;
            PreferredThirdPartyVendor = preferredThirdPartyVendor;
            TrustedUserAgents = trustedUserAgents;
        }
    }
}
