// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Outputs
{

    [OutputType]
    public sealed class GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyResponseCacheLookupResult
    {
        /// <summary>
        /// A list of context expressions whose values will be added to the base cache key. Values should contain an expression enclosed within ${} delimiters. Only the request context is available.
        /// </summary>
        public readonly ImmutableArray<string> CacheKeyAdditions;
        /// <summary>
        /// Whether this policy is currently enabled.
        /// </summary>
        public readonly bool IsEnabled;
        /// <summary>
        /// Set true to allow caching responses where the request has an Authorization header. Ensure you have configured your  cache key additions to get the level of isolation across authenticated requests that you require.
        /// </summary>
        public readonly bool IsPrivateCachingEnabled;
        /// <summary>
        /// Type of the Response Cache Store Policy.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyResponseCacheLookupResult(
            ImmutableArray<string> cacheKeyAdditions,

            bool isEnabled,

            bool isPrivateCachingEnabled,

            string type)
        {
            CacheKeyAdditions = cacheKeyAdditions;
            IsEnabled = isEnabled;
            IsPrivateCachingEnabled = isPrivateCachingEnabled;
            Type = type;
        }
    }
}