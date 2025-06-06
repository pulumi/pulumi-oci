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
    public sealed class GetDeploymentSpecificationRouteResult
    {
        /// <summary>
        /// The backend to forward requests to.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRouteBackendResult> Backends;
        /// <summary>
        /// Policies controlling the pushing of logs to Oracle Cloud Infrastructure Public Logging.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRouteLoggingPolicyResult> LoggingPolicies;
        /// <summary>
        /// A list of allowed methods on this route.
        /// </summary>
        public readonly ImmutableArray<string> Methods;
        /// <summary>
        /// A URL path pattern that must be matched on this route. The path pattern may contain a subset of RFC 6570 identifiers to allow wildcard and parameterized matching.
        /// </summary>
        public readonly string Path;
        /// <summary>
        /// Behavior applied to any requests received by the API on this route.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyResult> RequestPolicies;
        /// <summary>
        /// Behavior applied to any responses sent by the API for requests on this route.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRouteResponsePolicyResult> ResponsePolicies;

        [OutputConstructor]
        private GetDeploymentSpecificationRouteResult(
            ImmutableArray<Outputs.GetDeploymentSpecificationRouteBackendResult> backends,

            ImmutableArray<Outputs.GetDeploymentSpecificationRouteLoggingPolicyResult> loggingPolicies,

            ImmutableArray<string> methods,

            string path,

            ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyResult> requestPolicies,

            ImmutableArray<Outputs.GetDeploymentSpecificationRouteResponsePolicyResult> responsePolicies)
        {
            Backends = backends;
            LoggingPolicies = loggingPolicies;
            Methods = methods;
            Path = path;
            RequestPolicies = requestPolicies;
            ResponsePolicies = responsePolicies;
        }
    }
}
