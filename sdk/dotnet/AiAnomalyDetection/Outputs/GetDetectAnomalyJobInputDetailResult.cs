// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiAnomalyDetection.Outputs
{

    [OutputType]
    public sealed class GetDetectAnomalyJobInputDetailResult
    {
        public readonly string Content;
        public readonly string ContentType;
        public readonly ImmutableArray<Outputs.GetDetectAnomalyJobInputDetailDataResult> Datas;
        /// <summary>
        /// The type of input location Allowed values are:
        /// </summary>
        public readonly string InputType;
        /// <summary>
        /// Inline input details.
        /// </summary>
        public readonly string Message;
        /// <summary>
        /// List of ObjectLocations.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDetectAnomalyJobInputDetailObjectLocationResult> ObjectLocations;
        public readonly ImmutableArray<string> SignalNames;

        [OutputConstructor]
        private GetDetectAnomalyJobInputDetailResult(
            string content,

            string contentType,

            ImmutableArray<Outputs.GetDetectAnomalyJobInputDetailDataResult> datas,

            string inputType,

            string message,

            ImmutableArray<Outputs.GetDetectAnomalyJobInputDetailObjectLocationResult> objectLocations,

            ImmutableArray<string> signalNames)
        {
            Content = content;
            ContentType = contentType;
            Datas = datas;
            InputType = inputType;
            Message = message;
            ObjectLocations = objectLocations;
            SignalNames = signalNames;
        }
    }
}