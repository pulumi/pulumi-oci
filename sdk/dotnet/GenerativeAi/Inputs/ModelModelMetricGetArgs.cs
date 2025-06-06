// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GenerativeAi.Inputs
{

    public sealed class ModelModelMetricGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Fine-tuned model accuracy.
        /// </summary>
        [Input("finalAccuracy")]
        public Input<double>? FinalAccuracy { get; set; }

        /// <summary>
        /// Fine-tuned model loss.
        /// </summary>
        [Input("finalLoss")]
        public Input<double>? FinalLoss { get; set; }

        /// <summary>
        /// The type of the model metrics. Each type of model can expect a different set of model metrics.
        /// </summary>
        [Input("modelMetricsType")]
        public Input<string>? ModelMetricsType { get; set; }

        public ModelModelMetricGetArgs()
        {
        }
        public static new ModelModelMetricGetArgs Empty => new ModelModelMetricGetArgs();
    }
}
