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
    public sealed class GetCrossConnectsCrossConnectMacsecPropertyResult
    {
        /// <summary>
        /// Type of encryption cipher suite to use for the MACsec connection.
        /// </summary>
        public readonly string EncryptionCipher;
        /// <summary>
        /// Indicates whether unencrypted traffic is allowed if MACsec Key Agreement protocol (MKA) fails.
        /// </summary>
        public readonly bool IsUnprotectedTrafficAllowed;
        /// <summary>
        /// An object defining the Secrets-in-Vault OCIDs representing the MACsec key.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCrossConnectsCrossConnectMacsecPropertyPrimaryKeyResult> PrimaryKeys;
        /// <summary>
        /// A filter to return only resources that match the specified lifecycle state. The value is case insensitive.
        /// </summary>
        public readonly string State;

        [OutputConstructor]
        private GetCrossConnectsCrossConnectMacsecPropertyResult(
            string encryptionCipher,

            bool isUnprotectedTrafficAllowed,

            ImmutableArray<Outputs.GetCrossConnectsCrossConnectMacsecPropertyPrimaryKeyResult> primaryKeys,

            string state)
        {
            EncryptionCipher = encryptionCipher;
            IsUnprotectedTrafficAllowed = isUnprotectedTrafficAllowed;
            PrimaryKeys = primaryKeys;
            State = state;
        }
    }
}
