// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class DefaultSecurityListEgressSecurityRuleTcpOptionsSourcePortRangeGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("max", required: true)]
        public Input<int> Max { get; set; } = null!;

        [Input("min", required: true)]
        public Input<int> Min { get; set; } = null!;

        public DefaultSecurityListEgressSecurityRuleTcpOptionsSourcePortRangeGetArgs()
        {
        }
        public static new DefaultSecurityListEgressSecurityRuleTcpOptionsSourcePortRangeGetArgs Empty => new DefaultSecurityListEgressSecurityRuleTcpOptionsSourcePortRangeGetArgs();
    }
}
