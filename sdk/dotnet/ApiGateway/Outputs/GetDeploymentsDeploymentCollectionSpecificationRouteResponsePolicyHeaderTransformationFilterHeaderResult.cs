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
    public sealed class GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationFilterHeaderResult
    {
        /// <summary>
        /// The list of headers.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationFilterHeaderItemResult> Items;
        /// <summary>
        /// Type of the Response Cache Store Policy.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationFilterHeaderResult(
            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRouteResponsePolicyHeaderTransformationFilterHeaderItemResult> items,

            string type)
        {
            Items = items;
            Type = type;
        }
    }
}
