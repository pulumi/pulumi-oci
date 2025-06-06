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
    public sealed class DeploymentSpecificationRouteResponsePolicies
    {
        /// <summary>
        /// (Updatable) A set of transformations to apply to HTTP headers that pass through the gateway.
        /// </summary>
        public readonly Outputs.DeploymentSpecificationRouteResponsePoliciesHeaderTransformations? HeaderTransformations;
        /// <summary>
        /// (Updatable) Base policy for how a response from a backend is cached in the Response Cache.
        /// </summary>
        public readonly Outputs.DeploymentSpecificationRouteResponsePoliciesResponseCacheStore? ResponseCacheStore;

        [OutputConstructor]
        private DeploymentSpecificationRouteResponsePolicies(
            Outputs.DeploymentSpecificationRouteResponsePoliciesHeaderTransformations? headerTransformations,

            Outputs.DeploymentSpecificationRouteResponsePoliciesResponseCacheStore? responseCacheStore)
        {
            HeaderTransformations = headerTransformations;
            ResponseCacheStore = responseCacheStore;
        }
    }
}
