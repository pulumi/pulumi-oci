// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class CaptureFilterFlowLogCaptureFilterRuleTcpOptionsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable)
        /// </summary>
        [Input("destinationPortRange")]
        public Input<Inputs.CaptureFilterFlowLogCaptureFilterRuleTcpOptionsDestinationPortRangeGetArgs>? DestinationPortRange { get; set; }

        /// <summary>
        /// (Updatable)
        /// </summary>
        [Input("sourcePortRange")]
        public Input<Inputs.CaptureFilterFlowLogCaptureFilterRuleTcpOptionsSourcePortRangeGetArgs>? SourcePortRange { get; set; }

        public CaptureFilterFlowLogCaptureFilterRuleTcpOptionsGetArgs()
        {
        }
        public static new CaptureFilterFlowLogCaptureFilterRuleTcpOptionsGetArgs Empty => new CaptureFilterFlowLogCaptureFilterRuleTcpOptionsGetArgs();
    }
}