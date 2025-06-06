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
    public sealed class GetApiDeploymentSpecificationRouteResponsePolicyResult
    {
        /// <summary>
        /// A set of transformations to apply to HTTP headers that pass through the gateway.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationResult> HeaderTransformations;
        /// <summary>
        /// Base policy for how a response from a backend is cached in the Response Cache.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStoreResult> ResponseCacheStores;

        [OutputConstructor]
        private GetApiDeploymentSpecificationRouteResponsePolicyResult(
            ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationResult> headerTransformations,

            ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteResponsePolicyResponseCacheStoreResult> responseCacheStores)
        {
            HeaderTransformations = headerTransformations;
            ResponseCacheStores = responseCacheStores;
        }
    }
}
