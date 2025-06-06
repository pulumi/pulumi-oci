// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class DefaultSecurityListEgressSecurityRuleGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("destination", required: true)]
        public Input<string> Destination { get; set; } = null!;

        [Input("destinationType")]
        public Input<string>? DestinationType { get; set; }

        [Input("icmpOptions")]
        public Input<Inputs.DefaultSecurityListEgressSecurityRuleIcmpOptionsGetArgs>? IcmpOptions { get; set; }

        [Input("protocol", required: true)]
        public Input<string> Protocol { get; set; } = null!;

        [Input("stateless")]
        public Input<bool>? Stateless { get; set; }

        [Input("tcpOptions")]
        public Input<Inputs.DefaultSecurityListEgressSecurityRuleTcpOptionsGetArgs>? TcpOptions { get; set; }

        [Input("udpOptions")]
        public Input<Inputs.DefaultSecurityListEgressSecurityRuleUdpOptionsGetArgs>? UdpOptions { get; set; }

        public DefaultSecurityListEgressSecurityRuleGetArgs()
        {
        }
        public static new DefaultSecurityListEgressSecurityRuleGetArgs Empty => new DefaultSecurityListEgressSecurityRuleGetArgs();
    }
}
