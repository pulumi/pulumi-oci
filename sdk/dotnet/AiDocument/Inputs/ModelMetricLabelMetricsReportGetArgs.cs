// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiDocument.Inputs
{

    public sealed class ModelMetricLabelMetricsReportGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("confidenceEntries")]
        private InputList<Inputs.ModelMetricLabelMetricsReportConfidenceEntryGetArgs>? _confidenceEntries;

        /// <summary>
        /// List of document classification confidence report.
        /// </summary>
        public InputList<Inputs.ModelMetricLabelMetricsReportConfidenceEntryGetArgs> ConfidenceEntries
        {
            get => _confidenceEntries ?? (_confidenceEntries = new InputList<Inputs.ModelMetricLabelMetricsReportConfidenceEntryGetArgs>());
            set => _confidenceEntries = value;
        }

        /// <summary>
        /// Total test documents in the label.
        /// </summary>
        [Input("documentCount")]
        public Input<int>? DocumentCount { get; set; }

        /// <summary>
        /// Label name
        /// </summary>
        [Input("label")]
        public Input<string>? Label { get; set; }

        /// <summary>
        /// Mean average precision under different thresholds
        /// </summary>
        [Input("meanAveragePrecision")]
        public Input<double>? MeanAveragePrecision { get; set; }

        public ModelMetricLabelMetricsReportGetArgs()
        {
        }
        public static new ModelMetricLabelMetricsReportGetArgs Empty => new ModelMetricLabelMetricsReportGetArgs();
    }
}