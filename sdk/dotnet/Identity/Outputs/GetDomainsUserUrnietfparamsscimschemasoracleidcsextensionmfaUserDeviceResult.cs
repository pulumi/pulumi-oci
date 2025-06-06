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
    public sealed class GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserDeviceResult
    {
        /// <summary>
        /// The authentication method.
        /// </summary>
        public readonly string AuthenticationMethod;
        /// <summary>
        /// A human readable name, primarily used for display purposes.
        /// </summary>
        public readonly string Display;
        /// <summary>
        /// The device authentication factor status.
        /// </summary>
        public readonly string FactorStatus;
        /// <summary>
        /// Authentication Factor Type
        /// </summary>
        public readonly string FactorType;
        /// <summary>
        /// The last sync time for device.
        /// </summary>
        public readonly string LastSyncTime;
        /// <summary>
        /// User Token URI
        /// </summary>
        public readonly string Ref;
        /// <summary>
        /// A supplemental status indicating the reason why a user is disabled
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The third-party factor vendor name.
        /// </summary>
        public readonly string ThirdPartyVendorName;
        /// <summary>
        /// The value of a X509 certificate.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserDeviceResult(
            string authenticationMethod,

            string display,

            string factorStatus,

            string factorType,

            string lastSyncTime,

            string @ref,

            string status,

            string thirdPartyVendorName,

            string value)
        {
            AuthenticationMethod = authenticationMethod;
            Display = display;
            FactorStatus = factorStatus;
            FactorType = factorType;
            LastSyncTime = lastSyncTime;
            Ref = @ref;
            Status = status;
            ThirdPartyVendorName = thirdPartyVendorName;
            Value = value;
        }
    }
}
