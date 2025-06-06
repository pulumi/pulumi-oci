// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiLanguage.Inputs
{

    public sealed class ModelTestStrategyArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// This information will define the test strategy different datasets for test and validation(optional) dataset.
        /// </summary>
        [Input("strategyType", required: true)]
        public Input<string> StrategyType { get; set; } = null!;

        /// <summary>
        /// Possible data set type
        /// </summary>
        [Input("testingDataset", required: true)]
        public Input<Inputs.ModelTestStrategyTestingDatasetArgs> TestingDataset { get; set; } = null!;

        /// <summary>
        /// Possible data set type
        /// </summary>
        [Input("validationDataset")]
        public Input<Inputs.ModelTestStrategyValidationDatasetArgs>? ValidationDataset { get; set; }

        public ModelTestStrategyArgs()
        {
        }
        public static new ModelTestStrategyArgs Empty => new ModelTestStrategyArgs();
    }
}
