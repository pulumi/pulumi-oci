// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiAnomalyDetection.Inputs
{

    public sealed class ModelModelTrainingResultArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Accuracy metric for a signal.
        /// </summary>
        [Input("fap")]
        public Input<double>? Fap { get; set; }

        /// <summary>
        /// A boolean value to indicate if train goal/targetFap is achieved for trained model
        /// </summary>
        [Input("isTrainingGoalAchieved")]
        public Input<bool>? IsTrainingGoalAchieved { get; set; }

        /// <summary>
        /// The model accuracy metric on timestamp level.
        /// </summary>
        [Input("multivariateFap")]
        public Input<double>? MultivariateFap { get; set; }

        [Input("rowReductionDetails")]
        private InputList<Inputs.ModelModelTrainingResultRowReductionDetailArgs>? _rowReductionDetails;

        /// <summary>
        /// Information regarding how/what row reduction methods will be applied. If this property is not present or is null, then it means row reduction is not applied.
        /// </summary>
        public InputList<Inputs.ModelModelTrainingResultRowReductionDetailArgs> RowReductionDetails
        {
            get => _rowReductionDetails ?? (_rowReductionDetails = new InputList<Inputs.ModelModelTrainingResultRowReductionDetailArgs>());
            set => _rowReductionDetails = value;
        }

        [Input("signalDetails")]
        private InputList<Inputs.ModelModelTrainingResultSignalDetailArgs>? _signalDetails;

        /// <summary>
        /// The list of signal details.
        /// </summary>
        public InputList<Inputs.ModelModelTrainingResultSignalDetailArgs> SignalDetails
        {
            get => _signalDetails ?? (_signalDetails = new InputList<Inputs.ModelModelTrainingResultSignalDetailArgs>());
            set => _signalDetails = value;
        }

        /// <summary>
        /// A warning message to explain the reason when targetFap cannot be achieved for trained model
        /// </summary>
        [Input("warning")]
        public Input<string>? Warning { get; set; }

        public ModelModelTrainingResultArgs()
        {
        }
        public static new ModelModelTrainingResultArgs Empty => new ModelModelTrainingResultArgs();
    }
}