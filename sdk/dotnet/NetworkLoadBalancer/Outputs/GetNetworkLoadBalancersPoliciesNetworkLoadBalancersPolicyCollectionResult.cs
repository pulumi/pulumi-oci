// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkLoadBalancer.Outputs
{

    [OutputType]
    public sealed class GetNetworkLoadBalancersPoliciesNetworkLoadBalancersPolicyCollectionResult
    {
        /// <summary>
        /// Array of NetworkLoadBalancersPolicySummary objects.
        /// </summary>
        public readonly ImmutableArray<string> Items;

        [OutputConstructor]
        private GetNetworkLoadBalancersPoliciesNetworkLoadBalancersPolicyCollectionResult(ImmutableArray<string> items)
        {
            Items = items;
        }
    }
}
