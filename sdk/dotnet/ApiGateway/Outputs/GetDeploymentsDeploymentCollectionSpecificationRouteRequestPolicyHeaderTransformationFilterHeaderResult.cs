// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Outputs
{

    [OutputType]
    public sealed class GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeaderResult
    {
        /// <summary>
        /// The list of headers.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeaderItemResult> Items;
        /// <summary>
        /// Type of the Response Cache Store Policy.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeaderResult(
            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderTransformationFilterHeaderItemResult> items,

            string type)
        {
            Items = items;
            Type = type;
        }
    }
}
