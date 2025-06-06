// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Inputs
{

    public sealed class OnPremiseVantagePointWorkersSummaryAvailableCapabilityGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Capability of an On-premise vantage point worker.
        /// </summary>
        [Input("capability")]
        public Input<string>? Capability { get; set; }

        /// <summary>
        /// Count of available capability in a specific On-premise vantage point.
        /// </summary>
        [Input("onPremiseVantagePointCount")]
        public Input<int>? OnPremiseVantagePointCount { get; set; }

        public OnPremiseVantagePointWorkersSummaryAvailableCapabilityGetArgs()
        {
        }
        public static new OnPremiseVantagePointWorkersSummaryAvailableCapabilityGetArgs Empty => new OnPremiseVantagePointWorkersSummaryAvailableCapabilityGetArgs();
    }
}
