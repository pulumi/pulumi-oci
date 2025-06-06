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
    public sealed class GetModelMetricResult
    {
        /// <summary>
        /// Summary of count of samples used during model training.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetModelMetricDatasetSummaryResult> DatasetSummaries;
        /// <summary>
        /// List of metrics entries per label.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetModelMetricLabelMetricsReportResult> LabelMetricsReports;
        /// <summary>
        /// The type of the Document model.
        /// </summary>
        public readonly string ModelType;
        /// <summary>
        /// Overall Metrics report for Document Classification Model.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetModelMetricOverallMetricsReportResult> OverallMetricsReports;

        [OutputConstructor]
        private GetModelMetricResult(
            ImmutableArray<Outputs.GetModelMetricDatasetSummaryResult> datasetSummaries,

            ImmutableArray<Outputs.GetModelMetricLabelMetricsReportResult> labelMetricsReports,

            string modelType,

            ImmutableArray<Outputs.GetModelMetricOverallMetricsReportResult> overallMetricsReports)
        {
            DatasetSummaries = datasetSummaries;
            LabelMetricsReports = labelMetricsReports;
            ModelType = modelType;
            OverallMetricsReports = overallMetricsReports;
        }
    }
}
