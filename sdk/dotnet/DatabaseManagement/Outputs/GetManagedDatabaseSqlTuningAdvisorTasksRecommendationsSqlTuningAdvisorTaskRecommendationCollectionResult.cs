// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetManagedDatabaseSqlTuningAdvisorTasksRecommendationsSqlTuningAdvisorTaskRecommendationCollectionResult
    {
        /// <summary>
        /// A list of SQL Tuning Advisor recommendations.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabaseSqlTuningAdvisorTasksRecommendationsSqlTuningAdvisorTaskRecommendationCollectionItemResult> Items;

        [OutputConstructor]
        private GetManagedDatabaseSqlTuningAdvisorTasksRecommendationsSqlTuningAdvisorTaskRecommendationCollectionResult(ImmutableArray<Outputs.GetManagedDatabaseSqlTuningAdvisorTasksRecommendationsSqlTuningAdvisorTaskRecommendationCollectionItemResult> items)
        {
            Items = items;
        }
    }
}