// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MeteringComputation.Outputs
{

    [OutputType]
    public sealed class GetQueriesQueryCollectionItemQueryDefinitionResult
    {
        /// <summary>
        /// The common fields for Cost Analysis UI rendering.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetQueriesQueryCollectionItemQueryDefinitionCostAnalysisUiResult> CostAnalysisUis;
        /// <summary>
        /// The query display name. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The request of the generated Cost Analysis report.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetQueriesQueryCollectionItemQueryDefinitionReportQueryResult> ReportQueries;
        /// <summary>
        /// The saved query version.
        /// </summary>
        public readonly double Version;

        [OutputConstructor]
        private GetQueriesQueryCollectionItemQueryDefinitionResult(
            ImmutableArray<Outputs.GetQueriesQueryCollectionItemQueryDefinitionCostAnalysisUiResult> costAnalysisUis,

            string displayName,

            ImmutableArray<Outputs.GetQueriesQueryCollectionItemQueryDefinitionReportQueryResult> reportQueries,

            double version)
        {
            CostAnalysisUis = costAnalysisUis;
            DisplayName = displayName;
            ReportQueries = reportQueries;
            Version = version;
        }
    }
}
