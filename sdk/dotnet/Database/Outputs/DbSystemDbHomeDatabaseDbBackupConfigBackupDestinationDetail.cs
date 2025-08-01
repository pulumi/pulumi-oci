// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class DbSystemDbHomeDatabaseDbBackupConfigBackupDestinationDetail
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DBRS policy used for backup.
        /// </summary>
        public readonly string? DbrsPolicyId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// Indicates whether the backup destination is cross-region or local region.
        /// </summary>
        public readonly bool? IsRemote;
        /// <summary>
        /// The name of the remote region where the remote automatic incremental backups will be stored.
        /// 
        /// For information about valid region names, see [Regions and Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm).
        /// </summary>
        public readonly string? RemoteRegion;
        /// <summary>
        /// Type of the database backup destination.
        /// </summary>
        public readonly string? Type;

        [OutputConstructor]
        private DbSystemDbHomeDatabaseDbBackupConfigBackupDestinationDetail(
            string? dbrsPolicyId,

            string? id,

            bool? isRemote,

            string? remoteRegion,

            string? type)
        {
            DbrsPolicyId = dbrsPolicyId;
            Id = id;
            IsRemote = isRemote;
            RemoteRegion = remoteRegion;
            Type = type;
        }
    }
}
