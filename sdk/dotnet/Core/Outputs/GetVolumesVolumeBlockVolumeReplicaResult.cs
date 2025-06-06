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
    public sealed class GetVolumesVolumeBlockVolumeReplicaResult
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The block volume replica's Oracle ID (OCID).
        /// </summary>
        public readonly string BlockVolumeReplicaId;
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The OCID of the Vault service key which is the master encryption key for the volume.
        /// </summary>
        public readonly string KmsKeyId;
        public readonly string XrrKmsKeyId;

        [OutputConstructor]
        private GetVolumesVolumeBlockVolumeReplicaResult(
            string availabilityDomain,

            string blockVolumeReplicaId,

            string displayName,

            string kmsKeyId,

            string xrrKmsKeyId)
        {
            AvailabilityDomain = availabilityDomain;
            BlockVolumeReplicaId = blockVolumeReplicaId;
            DisplayName = displayName;
            KmsKeyId = kmsKeyId;
            XrrKmsKeyId = xrrKmsKeyId;
        }
    }
}
