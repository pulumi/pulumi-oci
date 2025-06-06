// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetAuditTrailAnalyticItemResult
    {
        /// <summary>
        /// Total count of aggregated metric.
        /// </summary>
        public readonly string Count;
        /// <summary>
        /// Details of aggregation dimensions used for summarizing audit trails.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAuditTrailAnalyticItemDimensionResult> Dimensions;

        [OutputConstructor]
        private GetAuditTrailAnalyticItemResult(
            string count,

            ImmutableArray<Outputs.GetAuditTrailAnalyticItemDimensionResult> dimensions)
        {
            Count = count;
            Dimensions = dimensions;
        }
    }
}
