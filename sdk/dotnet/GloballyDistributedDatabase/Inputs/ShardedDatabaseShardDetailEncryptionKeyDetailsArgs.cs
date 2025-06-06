// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GloballyDistributedDatabase.Inputs
{

    public sealed class ShardedDatabaseShardDetailEncryptionKeyDetailsArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the KMS key in vault identified by vaultId in customer tenancy  that is used as the master encryption key.
        /// </summary>
        [Input("kmsKeyId", required: true)]
        public Input<string> KmsKeyId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the KMS key version for key identified by kmsKeyId that is used in data encryption (TDE) operations.
        /// </summary>
        [Input("kmsKeyVersionId")]
        public Input<string>? KmsKeyVersionId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the vault in customer tenancy where KMS key is present. For shard or catalog with cross-region data guard enabled, user needs to make sure to provide virtual private vault only, which is also replicated in the region of standby shard.
        /// </summary>
        [Input("vaultId", required: true)]
        public Input<string> VaultId { get; set; } = null!;

        public ShardedDatabaseShardDetailEncryptionKeyDetailsArgs()
        {
        }
        public static new ShardedDatabaseShardDetailEncryptionKeyDetailsArgs Empty => new ShardedDatabaseShardDetailEncryptionKeyDetailsArgs();
    }
}
