// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetSecurityPolicyDeploymentsSecurityPolicyDeploymentCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetSecurityPolicyDeploymentsSecurityPolicyDeploymentCollectionItemResult> Items;

        [OutputConstructor]
        private GetSecurityPolicyDeploymentsSecurityPolicyDeploymentCollectionResult(ImmutableArray<Outputs.GetSecurityPolicyDeploymentsSecurityPolicyDeploymentCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
