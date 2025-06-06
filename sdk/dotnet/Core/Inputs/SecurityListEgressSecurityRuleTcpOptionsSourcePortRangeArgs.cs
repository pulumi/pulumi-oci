// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class SecurityListEgressSecurityRuleTcpOptionsSourcePortRangeArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The maximum port number. Must not be lower than the minimum port number. To specify a single port number, set both the min and max to the same value.
        /// </summary>
        [Input("max", required: true)]
        public Input<int> Max { get; set; } = null!;

        /// <summary>
        /// (Updatable) The minimum port number. Must not be greater than the maximum port number.
        /// </summary>
        [Input("min", required: true)]
        public Input<int> Min { get; set; } = null!;

        public SecurityListEgressSecurityRuleTcpOptionsSourcePortRangeArgs()
        {
        }
        public static new SecurityListEgressSecurityRuleTcpOptionsSourcePortRangeArgs Empty => new SecurityListEgressSecurityRuleTcpOptionsSourcePortRangeArgs();
    }
}
