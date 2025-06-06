// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemResult
    {
        /// <summary>
        /// The summary of the Managed Database resource.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemDatabaseResult> Databases;
        /// <summary>
        /// The errors in the Optimizer Statistics Advisor execution, if any.
        /// </summary>
        public readonly string ErrorMessage;
        /// <summary>
        /// The name of the Optimizer Statistics Advisor execution.
        /// </summary>
        public readonly string ExecutionName;
        /// <summary>
        /// The list of findings for the rule.
        /// </summary>
        public readonly int Findings;
        /// <summary>
        /// A report that includes the rules, findings, recommendations, and actions discovered during the execution of the Optimizer Statistics Advisor.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemReportResult> Reports;
        /// <summary>
        /// The status of the Optimizer Statistics Advisor execution.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The Optimizer Statistics Advisor execution status message, if any.
        /// </summary>
        public readonly string StatusMessage;
        /// <summary>
        /// The name of the Optimizer Statistics Advisor task.
        /// </summary>
        public readonly string TaskName;
        /// <summary>
        /// The end time of the time range to retrieve the Optimizer Statistics Advisor execution of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
        /// </summary>
        public readonly string TimeEnd;
        /// <summary>
        /// The start time of the time range to retrieve the Optimizer Statistics Advisor execution of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
        /// </summary>
        public readonly string TimeStart;

        [OutputConstructor]
        private GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemResult(
            ImmutableArray<Outputs.GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemDatabaseResult> databases,

            string errorMessage,

            string executionName,

            int findings,

            ImmutableArray<Outputs.GetManagedDatabaseOptimizerStatisticsAdvisorExecutionsOptimizerStatisticsAdvisorExecutionsCollectionItemReportResult> reports,

            string status,

            string statusMessage,

            string taskName,

            string timeEnd,

            string timeStart)
        {
            Databases = databases;
            ErrorMessage = errorMessage;
            ExecutionName = executionName;
            Findings = findings;
            Reports = reports;
            Status = status;
            StatusMessage = statusMessage;
            TaskName = taskName;
            TimeEnd = timeEnd;
            TimeStart = timeStart;
        }
    }
}
