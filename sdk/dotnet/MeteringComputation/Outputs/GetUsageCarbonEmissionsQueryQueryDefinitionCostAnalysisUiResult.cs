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
    public sealed class GetUsageCarbonEmissionsQueryQueryDefinitionCostAnalysisUiResult
    {
        /// <summary>
        /// The graph type.
        /// </summary>
        public readonly string Graph;
        /// <summary>
        /// A cumulative graph.
        /// </summary>
        public readonly bool IsCumulativeGraph;

        [OutputConstructor]
        private GetUsageCarbonEmissionsQueryQueryDefinitionCostAnalysisUiResult(
            string graph,

            bool isCumulativeGraph)
        {
            Graph = graph;
            IsCumulativeGraph = isCumulativeGraph;
        }
    }
}
