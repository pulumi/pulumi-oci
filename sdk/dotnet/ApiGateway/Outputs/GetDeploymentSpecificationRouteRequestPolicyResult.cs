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
    public sealed class GetDeploymentSpecificationRouteRequestPolicyResult
    {
        /// <summary>
        /// If authentication has been performed, validate whether the request scope (if any) applies to this route. If no RouteAuthorizationPolicy is defined for a route, a policy with a type of AUTHENTICATION_ONLY is applied.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyAuthorizationResult> Authorizations;
        /// <summary>
        /// Validate the payload body of the incoming API requests on a specific route.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyBodyValidationResult> BodyValidations;
        /// <summary>
        /// Enable CORS (Cross-Origin-Resource-Sharing) request handling.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyCorResult> Cors;
        /// <summary>
        /// A set of transformations to apply to HTTP headers that pass through the gateway.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationResult> HeaderTransformations;
        /// <summary>
        /// Validate the HTTP headers on the incoming API requests on a specific route.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyHeaderValidationResult> HeaderValidations;
        /// <summary>
        /// A set of transformations to apply to query parameters that pass through the gateway.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationResult> QueryParameterTransformations;
        /// <summary>
        /// Validate the URL query parameters on the incoming API requests on a specific route.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyQueryParameterValidationResult> QueryParameterValidations;
        /// <summary>
        /// Base policy for Response Cache lookup.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyResponseCacheLookupResult> ResponseCacheLookups;

        [OutputConstructor]
        private GetDeploymentSpecificationRouteRequestPolicyResult(
            ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyAuthorizationResult> authorizations,

            ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyBodyValidationResult> bodyValidations,

            ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyCorResult> cors,

            ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyHeaderTransformationResult> headerTransformations,

            ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyHeaderValidationResult> headerValidations,

            ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyQueryParameterTransformationResult> queryParameterTransformations,

            ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyQueryParameterValidationResult> queryParameterValidations,

            ImmutableArray<Outputs.GetDeploymentSpecificationRouteRequestPolicyResponseCacheLookupResult> responseCacheLookups)
        {
            Authorizations = authorizations;
            BodyValidations = bodyValidations;
            Cors = cors;
            HeaderTransformations = headerTransformations;
            HeaderValidations = headerValidations;
            QueryParameterTransformations = queryParameterTransformations;
            QueryParameterValidations = queryParameterValidations;
            ResponseCacheLookups = responseCacheLookups;
        }
    }
}