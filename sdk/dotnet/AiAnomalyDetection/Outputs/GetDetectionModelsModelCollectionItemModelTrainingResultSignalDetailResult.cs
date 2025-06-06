// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiAnomalyDetection.Outputs
{

    [OutputType]
    public sealed class GetDetectionModelsModelCollectionItemModelTrainingResultSignalDetailResult
    {
        /// <summary>
        /// detailed information for a signal.
        /// </summary>
        public readonly string Details;
        /// <summary>
        /// Accuracy metric for a signal.
        /// </summary>
        public readonly double Fap;
        /// <summary>
        /// A boolean value to indicate if a signal is quantized or not.
        /// </summary>
        public readonly bool IsQuantized;
        /// <summary>
        /// Max value within a signal.
        /// </summary>
        public readonly double Max;
        /// <summary>
        /// Min value within a signal.
        /// </summary>
        public readonly double Min;
        /// <summary>
        /// The ratio of missing values in a signal filled/imputed by the IDP algorithm.
        /// </summary>
        public readonly double MviRatio;
        /// <summary>
        /// The name of a signal.
        /// </summary>
        public readonly string SignalName;
        /// <summary>
        /// Status of the signal:
        /// * ACCEPTED - the signal is used for training the model
        /// * DROPPED - the signal does not meet requirement, and is dropped before training the model.
        /// * OTHER - placeholder for other status
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// Standard deviation of values within a signal.
        /// </summary>
        public readonly double Std;

        [OutputConstructor]
        private GetDetectionModelsModelCollectionItemModelTrainingResultSignalDetailResult(
            string details,

            double fap,

            bool isQuantized,

            double max,

            double min,

            double mviRatio,

            string signalName,

            string status,

            double std)
        {
            Details = details;
            Fap = fap;
            IsQuantized = isQuantized;
            Max = max;
            Min = min;
            MviRatio = mviRatio;
            SignalName = signalName;
            Status = status;
            Std = std;
        }
    }
}
