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
    public sealed class VolumeBlockVolumeReplica
    {
        /// <summary>
        /// (Updatable) The availability domain of the block volume replica.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The block volume replica's Oracle ID (OCID).
        /// </summary>
        public readonly string? BlockVolumeReplicaId;
        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// (Updatable) The OCID of the Vault service key to assign as the master encryption key for the volume.
        /// </summary>
        public readonly string? KmsKeyId;
        /// <summary>
        /// (Updatable) The OCID of the Vault service key which is the master encryption key for the cross region block volume replicas, which will be used in the destination region to encrypt the block volume replica's encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
        /// </summary>
        public readonly string? XrrKmsKeyId;

        [OutputConstructor]
        private VolumeBlockVolumeReplica(
            string availabilityDomain,

            string? blockVolumeReplicaId,

            string? displayName,

            string? kmsKeyId,

            string? xrrKmsKeyId)
        {
            AvailabilityDomain = availabilityDomain;
            BlockVolumeReplicaId = blockVolumeReplicaId;
            DisplayName = displayName;
            KmsKeyId = kmsKeyId;
            XrrKmsKeyId = xrrKmsKeyId;
        }
    }
}
