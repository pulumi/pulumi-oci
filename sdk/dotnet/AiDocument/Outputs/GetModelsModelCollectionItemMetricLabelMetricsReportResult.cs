// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiDocument.Outputs
{

    [OutputType]
    public sealed class GetModelsModelCollectionItemMetricLabelMetricsReportResult
    {
        /// <summary>
        /// List of document classification confidence report.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetModelsModelCollectionItemMetricLabelMetricsReportConfidenceEntryResult> ConfidenceEntries;
        /// <summary>
        /// Total test documents in the label.
        /// </summary>
        public readonly int DocumentCount;
        /// <summary>
        /// Label name
        /// </summary>
        public readonly string Label;
        /// <summary>
        /// Mean average precision under different thresholds
        /// </summary>
        public readonly double MeanAveragePrecision;

        [OutputConstructor]
        private GetModelsModelCollectionItemMetricLabelMetricsReportResult(
            ImmutableArray<Outputs.GetModelsModelCollectionItemMetricLabelMetricsReportConfidenceEntryResult> confidenceEntries,

            int documentCount,

            string label,

            double meanAveragePrecision)
        {
            ConfidenceEntries = confidenceEntries;
            DocumentCount = documentCount;
            Label = label;
            MeanAveragePrecision = meanAveragePrecision;
        }
    }
}
