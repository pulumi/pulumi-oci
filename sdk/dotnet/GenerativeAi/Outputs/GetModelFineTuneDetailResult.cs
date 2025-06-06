// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GenerativeAi.Outputs
{

    [OutputType]
    public sealed class GetModelFineTuneDetailResult
    {
        /// <summary>
        /// The OCID of the dedicated AI cluster this fine-tuning runs on.
        /// </summary>
        public readonly string DedicatedAiClusterId;
        /// <summary>
        /// The fine-tuning method and hyperparameters used for fine-tuning a custom model.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetModelFineTuneDetailTrainingConfigResult> TrainingConfigs;
        /// <summary>
        /// The dataset used to fine-tune the model.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetModelFineTuneDetailTrainingDatasetResult> TrainingDatasets;

        [OutputConstructor]
        private GetModelFineTuneDetailResult(
            string dedicatedAiClusterId,

            ImmutableArray<Outputs.GetModelFineTuneDetailTrainingConfigResult> trainingConfigs,

            ImmutableArray<Outputs.GetModelFineTuneDetailTrainingDatasetResult> trainingDatasets)
        {
            DedicatedAiClusterId = dedicatedAiClusterId;
            TrainingConfigs = trainingConfigs;
            TrainingDatasets = trainingDatasets;
        }
    }
}
