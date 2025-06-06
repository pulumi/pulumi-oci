// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiLanguage.Inputs
{

    public sealed class ModelEvaluationResultArgs : global::Pulumi.ResourceArgs
    {
        [Input("classMetrics")]
        private InputList<Inputs.ModelEvaluationResultClassMetricArgs>? _classMetrics;

        /// <summary>
        /// List of text classification metrics
        /// </summary>
        public InputList<Inputs.ModelEvaluationResultClassMetricArgs> ClassMetrics
        {
            get => _classMetrics ?? (_classMetrics = new InputList<Inputs.ModelEvaluationResultClassMetricArgs>());
            set => _classMetrics = value;
        }

        /// <summary>
        /// class level confusion matrix
        /// </summary>
        [Input("confusionMatrix")]
        public Input<string>? ConfusionMatrix { get; set; }

        [Input("entityMetrics")]
        private InputList<Inputs.ModelEvaluationResultEntityMetricArgs>? _entityMetrics;

        /// <summary>
        /// List of entity metrics
        /// </summary>
        public InputList<Inputs.ModelEvaluationResultEntityMetricArgs> EntityMetrics
        {
            get => _entityMetrics ?? (_entityMetrics = new InputList<Inputs.ModelEvaluationResultEntityMetricArgs>());
            set => _entityMetrics = value;
        }

        [Input("labels")]
        private InputList<string>? _labels;

        /// <summary>
        /// labels
        /// </summary>
        public InputList<string> Labels
        {
            get => _labels ?? (_labels = new InputList<string>());
            set => _labels = value;
        }

        [Input("metrics")]
        private InputList<Inputs.ModelEvaluationResultMetricArgs>? _metrics;

        /// <summary>
        /// Model level named entity recognition metrics
        /// </summary>
        public InputList<Inputs.ModelEvaluationResultMetricArgs> Metrics
        {
            get => _metrics ?? (_metrics = new InputList<Inputs.ModelEvaluationResultMetricArgs>());
            set => _metrics = value;
        }

        /// <summary>
        /// Model type
        /// </summary>
        [Input("modelType")]
        public Input<string>? ModelType { get; set; }

        public ModelEvaluationResultArgs()
        {
        }
        public static new ModelEvaluationResultArgs Empty => new ModelEvaluationResultArgs();
    }
}
