// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiLanguage.Inputs
{

    public sealed class ModelEvaluationResultMetricArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The fraction of the labels that were correctly recognised .
        /// </summary>
        [Input("accuracy")]
        public Input<double>? Accuracy { get; set; }

        /// <summary>
        /// F1-score, is a measure of a model’s accuracy on a dataset
        /// </summary>
        [Input("macroF1")]
        public Input<double>? MacroF1 { get; set; }

        /// <summary>
        /// Precision refers to the number of true positives divided by the total number of positive predictions (i.e., the number of true positives plus the number of false positives)
        /// </summary>
        [Input("macroPrecision")]
        public Input<double>? MacroPrecision { get; set; }

        /// <summary>
        /// Measures the model's ability to predict actual positive classes. It is the ratio between the predicted true positives and what was actually tagged. The recall metric reveals how many of the predicted classes are correct.
        /// </summary>
        [Input("macroRecall")]
        public Input<double>? MacroRecall { get; set; }

        /// <summary>
        /// F1-score, is a measure of a model’s accuracy on a dataset
        /// </summary>
        [Input("microF1")]
        public Input<double>? MicroF1 { get; set; }

        /// <summary>
        /// Precision refers to the number of true positives divided by the total number of positive predictions (i.e., the number of true positives plus the number of false positives)
        /// </summary>
        [Input("microPrecision")]
        public Input<double>? MicroPrecision { get; set; }

        /// <summary>
        /// Measures the model's ability to predict actual positive classes. It is the ratio between the predicted true positives and what was actually tagged. The recall metric reveals how many of the predicted classes are correct.
        /// </summary>
        [Input("microRecall")]
        public Input<double>? MicroRecall { get; set; }

        /// <summary>
        /// F1-score, is a measure of a model’s accuracy on a dataset
        /// </summary>
        [Input("weightedF1")]
        public Input<double>? WeightedF1 { get; set; }

        /// <summary>
        /// Precision refers to the number of true positives divided by the total number of positive predictions (i.e., the number of true positives plus the number of false positives)
        /// </summary>
        [Input("weightedPrecision")]
        public Input<double>? WeightedPrecision { get; set; }

        /// <summary>
        /// Measures the model's ability to predict actual positive classes. It is the ratio between the predicted true positives and what was actually tagged. The recall metric reveals how many of the predicted classes are correct.
        /// </summary>
        [Input("weightedRecall")]
        public Input<double>? WeightedRecall { get; set; }

        public ModelEvaluationResultMetricArgs()
        {
        }
        public static new ModelEvaluationResultMetricArgs Empty => new ModelEvaluationResultMetricArgs();
    }
}
