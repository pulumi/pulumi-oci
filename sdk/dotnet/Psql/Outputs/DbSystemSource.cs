// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Psql.Outputs
{

    [OutputType]
    public sealed class DbSystemSource
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database system backup.
        /// </summary>
        public readonly string? BackupId;
        /// <summary>
        /// Deprecated. Don't use.
        /// </summary>
        public readonly bool? IsHavingRestoreConfigOverrides;
        /// <summary>
        /// The source descriminator. Example: `{"source_type": "BACKUP"}`.
        /// </summary>
        public readonly string SourceType;

        [OutputConstructor]
        private DbSystemSource(
            string? backupId,

            bool? isHavingRestoreConfigOverrides,

            string sourceType)
        {
            BackupId = backupId;
            IsHavingRestoreConfigOverrides = isHavingRestoreConfigOverrides;
            SourceType = sourceType;
        }
    }
}
