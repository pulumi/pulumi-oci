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
    public sealed class GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryResult
    {
        /// <summary>
        /// The OCID of the current execution window.
        /// </summary>
        public readonly string CurrentExecutionWindow;
        /// <summary>
        /// List of database server history details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetailResult> DbServersHistoryDetails;
        /// <summary>
        /// The list of granular maintenance history details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryResult> GranularMaintenanceHistories;
        /// <summary>
        /// The OCID of the maintenance run.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Details of a maintenance run.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryMaintenanceRunDetailResult> MaintenanceRunDetails;

        [OutputConstructor]
        private GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryResult(
            string currentExecutionWindow,

            ImmutableArray<Outputs.GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryDbServersHistoryDetailResult> dbServersHistoryDetails,

            ImmutableArray<Outputs.GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryGranularMaintenanceHistoryResult> granularMaintenanceHistories,

            string id,

            ImmutableArray<Outputs.GetDatabaseMaintenanceRunHistoriesMaintenanceRunHistoryMaintenanceRunDetailResult> maintenanceRunDetails)
        {
            CurrentExecutionWindow = currentExecutionWindow;
            DbServersHistoryDetails = dbServersHistoryDetails;
            GranularMaintenanceHistories = granularMaintenanceHistories;
            Id = id;
            MaintenanceRunDetails = maintenanceRunDetails;
        }
    }
}
