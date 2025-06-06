// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class NetworkSecurityGroupSecurityRuleTcpOptionsGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("destinationPortRange")]
        public Input<Inputs.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeGetArgs>? DestinationPortRange { get; set; }

        [Input("sourcePortRange")]
        public Input<Inputs.NetworkSecurityGroupSecurityRuleTcpOptionsSourcePortRangeGetArgs>? SourcePortRange { get; set; }

        public NetworkSecurityGroupSecurityRuleTcpOptionsGetArgs()
        {
        }
        public static new NetworkSecurityGroupSecurityRuleTcpOptionsGetArgs Empty => new NetworkSecurityGroupSecurityRuleTcpOptionsGetArgs();
    }
}
