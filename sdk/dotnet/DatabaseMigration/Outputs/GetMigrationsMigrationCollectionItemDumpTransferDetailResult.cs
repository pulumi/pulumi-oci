// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Outputs
{

    [OutputType]
    public sealed class GetMigrationsMigrationCollectionItemDumpTransferDetailResult
    {
        /// <summary>
        /// Optional additional properties for dump transfer in source or target host. Default kind is CURL
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMigrationsMigrationCollectionItemDumpTransferDetailSourceResult> Sources;
        /// <summary>
        /// Optional additional properties for dump transfer in source or target host. Default kind is CURL
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMigrationsMigrationCollectionItemDumpTransferDetailTargetResult> Targets;

        [OutputConstructor]
        private GetMigrationsMigrationCollectionItemDumpTransferDetailResult(
            ImmutableArray<Outputs.GetMigrationsMigrationCollectionItemDumpTransferDetailSourceResult> sources,

            ImmutableArray<Outputs.GetMigrationsMigrationCollectionItemDumpTransferDetailTargetResult> targets)
        {
            Sources = sources;
            Targets = targets;
        }
    }
}