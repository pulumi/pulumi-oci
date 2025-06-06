// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetAuthenticationPolicyNetworkPolicyResult
    {
        /// <summary>
        /// Network Source ids
        /// </summary>
        public readonly ImmutableArray<string> NetworkSourceIds;

        [OutputConstructor]
        private GetAuthenticationPolicyNetworkPolicyResult(ImmutableArray<string> networkSourceIds)
        {
            NetworkSourceIds = networkSourceIds;
        }
    }
}
