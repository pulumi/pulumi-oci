// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiDocument.Inputs
{

    public sealed class ModelMetricDatasetSummaryGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Number of samples used for testing the model.
        /// </summary>
        [Input("testSampleCount")]
        public Input<int>? TestSampleCount { get; set; }

        /// <summary>
        /// Number of samples used for training the model.
        /// </summary>
        [Input("trainingSampleCount")]
        public Input<int>? TrainingSampleCount { get; set; }

        /// <summary>
        /// Number of samples used for validating the model.
        /// </summary>
        [Input("validationSampleCount")]
        public Input<int>? ValidationSampleCount { get; set; }

        public ModelMetricDatasetSummaryGetArgs()
        {
        }
        public static new ModelMetricDatasetSummaryGetArgs Empty => new ModelMetricDatasetSummaryGetArgs();
    }
}
