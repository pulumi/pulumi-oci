// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate.Outputs
{

    [OutputType]
    public sealed class GetDeploymentsDeploymentCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemResult> Items;

        [OutputConstructor]
        private GetDeploymentsDeploymentCollectionResult(ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
