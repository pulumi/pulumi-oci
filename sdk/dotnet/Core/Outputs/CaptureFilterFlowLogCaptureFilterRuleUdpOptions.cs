// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class CaptureFilterFlowLogCaptureFilterRuleUdpOptions
    {
        /// <summary>
        /// (Updatable)
        /// </summary>
        public readonly Outputs.CaptureFilterFlowLogCaptureFilterRuleUdpOptionsDestinationPortRange? DestinationPortRange;
        /// <summary>
        /// (Updatable)
        /// </summary>
        public readonly Outputs.CaptureFilterFlowLogCaptureFilterRuleUdpOptionsSourcePortRange? SourcePortRange;

        [OutputConstructor]
        private CaptureFilterFlowLogCaptureFilterRuleUdpOptions(
            Outputs.CaptureFilterFlowLogCaptureFilterRuleUdpOptionsDestinationPortRange? destinationPortRange,

            Outputs.CaptureFilterFlowLogCaptureFilterRuleUdpOptionsSourcePortRange? sourcePortRange)
        {
            DestinationPortRange = destinationPortRange;
            SourcePortRange = sourcePortRange;
        }
    }
}