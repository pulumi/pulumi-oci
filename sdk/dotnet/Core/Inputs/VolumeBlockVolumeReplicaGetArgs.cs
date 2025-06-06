// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class VolumeBlockVolumeReplicaGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The availability domain of the block volume replica.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain", required: true)]
        public Input<string> AvailabilityDomain { get; set; } = null!;

        /// <summary>
        /// The block volume replica's Oracle ID (OCID).
        /// </summary>
        [Input("blockVolumeReplicaId")]
        public Input<string>? BlockVolumeReplicaId { get; set; }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the Vault service key to assign as the master encryption key for the volume.
        /// </summary>
        [Input("kmsKeyId")]
        public Input<string>? KmsKeyId { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the Vault service key which is the master encryption key for the cross region block volume replicas, which will be used in the destination region to encrypt the block volume replica's encryption keys. For more information about the Vault service and encryption keys, see [Overview of Vault service](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm) and [Using Keys](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Tasks/usingkeys.htm).
        /// </summary>
        [Input("xrrKmsKeyId")]
        public Input<string>? XrrKmsKeyId { get; set; }

        public VolumeBlockVolumeReplicaGetArgs()
        {
        }
        public static new VolumeBlockVolumeReplicaGetArgs Empty => new VolumeBlockVolumeReplicaGetArgs();
    }
}
