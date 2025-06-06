// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetIpsecConnectionTunnelsIpSecConnectionTunnelPhaseOneDetailResult
    {
        /// <summary>
        /// Phase two authentication algorithm proposed during tunnel negotiation.
        /// </summary>
        public readonly string CustomAuthenticationAlgorithm;
        /// <summary>
        /// The proposed custom Diffie-Hellman group.
        /// </summary>
        public readonly string CustomDhGroup;
        /// <summary>
        /// The proposed custom phase two encryption algorithm.
        /// </summary>
        public readonly string CustomEncryptionAlgorithm;
        /// <summary>
        /// Indicates whether custom phase one configuration is enabled. If this option is not enabled, default settings are proposed.
        /// </summary>
        public readonly bool IsCustomPhaseOneConfig;
        /// <summary>
        /// Indicates whether IKE phase one is established.
        /// </summary>
        public readonly bool IsIkeEstablished;
        /// <summary>
        /// The total configured lifetime of the IKE security association.
        /// </summary>
        public readonly int Lifetime;
        /// <summary>
        /// The negotiated phase two authentication algorithm.
        /// </summary>
        public readonly string NegotiatedAuthenticationAlgorithm;
        /// <summary>
        /// The negotiated Diffie-Hellman group.
        /// </summary>
        public readonly string NegotiatedDhGroup;
        /// <summary>
        /// The negotiated encryption algorithm.
        /// </summary>
        public readonly string NegotiatedEncryptionAlgorithm;
        public readonly string RemainingLifetime;
        /// <summary>
        /// The remaining lifetime before the key is refreshed.
        /// </summary>
        public readonly int RemainingLifetimeInt;
        /// <summary>
        /// The date and time the remaining lifetime was last retrieved, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string RemainingLifetimeLastRetrieved;

        [OutputConstructor]
        private GetIpsecConnectionTunnelsIpSecConnectionTunnelPhaseOneDetailResult(
            string customAuthenticationAlgorithm,

            string customDhGroup,

            string customEncryptionAlgorithm,

            bool isCustomPhaseOneConfig,

            bool isIkeEstablished,

            int lifetime,

            string negotiatedAuthenticationAlgorithm,

            string negotiatedDhGroup,

            string negotiatedEncryptionAlgorithm,

            string remainingLifetime,

            int remainingLifetimeInt,

            string remainingLifetimeLastRetrieved)
        {
            CustomAuthenticationAlgorithm = customAuthenticationAlgorithm;
            CustomDhGroup = customDhGroup;
            CustomEncryptionAlgorithm = customEncryptionAlgorithm;
            IsCustomPhaseOneConfig = isCustomPhaseOneConfig;
            IsIkeEstablished = isIkeEstablished;
            Lifetime = lifetime;
            NegotiatedAuthenticationAlgorithm = negotiatedAuthenticationAlgorithm;
            NegotiatedDhGroup = negotiatedDhGroup;
            NegotiatedEncryptionAlgorithm = negotiatedEncryptionAlgorithm;
            RemainingLifetime = remainingLifetime;
            RemainingLifetimeInt = remainingLifetimeInt;
            RemainingLifetimeLastRetrieved = remainingLifetimeLastRetrieved;
        }
    }
}
