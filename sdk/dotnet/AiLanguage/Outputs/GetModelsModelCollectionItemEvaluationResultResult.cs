// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiLanguage.Outputs
{

    [OutputType]
    public sealed class GetModelsModelCollectionItemEvaluationResultResult
    {
        /// <summary>
        /// List of text classification metrics
        /// </summary>
        public readonly ImmutableArray<Outputs.GetModelsModelCollectionItemEvaluationResultClassMetricResult> ClassMetrics;
        /// <summary>
        /// class level confusion matrix
        /// </summary>
        public readonly string ConfusionMatrix;
        /// <summary>
        /// List of entity metrics
        /// </summary>
        public readonly ImmutableArray<Outputs.GetModelsModelCollectionItemEvaluationResultEntityMetricResult> EntityMetrics;
        /// <summary>
        /// labels
        /// </summary>
        public readonly ImmutableArray<string> Labels;
        /// <summary>
        /// Model level named entity recognition metrics
        /// </summary>
        public readonly ImmutableArray<Outputs.GetModelsModelCollectionItemEvaluationResultMetricResult> Metrics;
        /// <summary>
        /// Model type
        /// </summary>
        public readonly string ModelType;

        [OutputConstructor]
        private GetModelsModelCollectionItemEvaluationResultResult(
            ImmutableArray<Outputs.GetModelsModelCollectionItemEvaluationResultClassMetricResult> classMetrics,

            string confusionMatrix,

            ImmutableArray<Outputs.GetModelsModelCollectionItemEvaluationResultEntityMetricResult> entityMetrics,

            ImmutableArray<string> labels,

            ImmutableArray<Outputs.GetModelsModelCollectionItemEvaluationResultMetricResult> metrics,

            string modelType)
        {
            ClassMetrics = classMetrics;
            ConfusionMatrix = confusionMatrix;
            EntityMetrics = entityMetrics;
            Labels = labels;
            Metrics = metrics;
            ModelType = modelType;
        }
    }
}
