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
    public sealed class GetDatabaseMaintenanceRunHistoryDbServersHistoryDetailResult
    {
        /// <summary>
        /// The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDatabaseMaintenanceRunHistoryDbServersHistoryDetailDbServerPatchingDetailResult> DbServerPatchingDetails;
        /// <summary>
        /// The user-friendly name for the maintenance run.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The OCID of the maintenance run.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetDatabaseMaintenanceRunHistoryDbServersHistoryDetailResult(
            ImmutableArray<Outputs.GetDatabaseMaintenanceRunHistoryDbServersHistoryDetailDbServerPatchingDetailResult> dbServerPatchingDetails,

            string displayName,

            string id)
        {
            DbServerPatchingDetails = dbServerPatchingDetails;
            DisplayName = displayName;
            Id = id;
        }
    }
}
