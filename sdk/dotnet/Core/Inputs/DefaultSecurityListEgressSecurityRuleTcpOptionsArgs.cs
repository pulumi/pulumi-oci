// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class DefaultSecurityListEgressSecurityRuleTcpOptionsArgs : global::Pulumi.ResourceArgs
    {
        [Input("max")]
        public Input<int>? Max { get; set; }

        [Input("min")]
        public Input<int>? Min { get; set; }

        [Input("sourcePortRange")]
        public Input<Inputs.DefaultSecurityListEgressSecurityRuleTcpOptionsSourcePortRangeArgs>? SourcePortRange { get; set; }

        public DefaultSecurityListEgressSecurityRuleTcpOptionsArgs()
        {
        }
        public static new DefaultSecurityListEgressSecurityRuleTcpOptionsArgs Empty => new DefaultSecurityListEgressSecurityRuleTcpOptionsArgs();
    }
}