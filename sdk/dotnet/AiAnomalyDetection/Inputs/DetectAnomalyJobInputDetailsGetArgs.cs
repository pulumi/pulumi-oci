// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiAnomalyDetection.Inputs
{

    public sealed class DetectAnomalyJobInputDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("content")]
        public Input<string>? Content { get; set; }

        [Input("contentType")]
        public Input<string>? ContentType { get; set; }

        [Input("datas")]
        private InputList<Inputs.DetectAnomalyJobInputDetailsDataGetArgs>? _datas;

        /// <summary>
        /// Array containing data.
        /// </summary>
        public InputList<Inputs.DetectAnomalyJobInputDetailsDataGetArgs> Datas
        {
            get => _datas ?? (_datas = new InputList<Inputs.DetectAnomalyJobInputDetailsDataGetArgs>());
            set => _datas = value;
        }

        /// <summary>
        /// Type of request. This parameter is automatically populated by classes generated by the SDK. For raw curl requests, you must provide this field.
        /// </summary>
        [Input("inputType", required: true)]
        public Input<string> InputType { get; set; } = null!;

        /// <summary>
        /// Inline input details.
        /// </summary>
        [Input("message")]
        public Input<string>? Message { get; set; }

        [Input("objectLocations")]
        private InputList<Inputs.DetectAnomalyJobInputDetailsObjectLocationGetArgs>? _objectLocations;

        /// <summary>
        /// List of ObjectLocations.
        /// </summary>
        public InputList<Inputs.DetectAnomalyJobInputDetailsObjectLocationGetArgs> ObjectLocations
        {
            get => _objectLocations ?? (_objectLocations = new InputList<Inputs.DetectAnomalyJobInputDetailsObjectLocationGetArgs>());
            set => _objectLocations = value;
        }

        [Input("signalNames")]
        private InputList<string>? _signalNames;

        /// <summary>
        /// List of signal names.
        /// </summary>
        public InputList<string> SignalNames
        {
            get => _signalNames ?? (_signalNames = new InputList<string>());
            set => _signalNames = value;
        }

        public DetectAnomalyJobInputDetailsGetArgs()
        {
        }
        public static new DetectAnomalyJobInputDetailsGetArgs Empty => new DetectAnomalyJobInputDetailsGetArgs();
    }
}