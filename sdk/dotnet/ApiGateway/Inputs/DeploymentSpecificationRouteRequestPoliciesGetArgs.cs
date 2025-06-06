// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRouteRequestPoliciesGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) If authentication has been performed, validate whether the request scope (if any) applies to this route. If no RouteAuthorizationPolicy is defined for a route, a policy with a type of AUTHENTICATION_ONLY is applied.
        /// </summary>
        [Input("authorization")]
        public Input<Inputs.DeploymentSpecificationRouteRequestPoliciesAuthorizationGetArgs>? Authorization { get; set; }

        /// <summary>
        /// (Updatable) Validate the payload body of the incoming API requests on a specific route.
        /// </summary>
        [Input("bodyValidation")]
        public Input<Inputs.DeploymentSpecificationRouteRequestPoliciesBodyValidationGetArgs>? BodyValidation { get; set; }

        /// <summary>
        /// (Updatable) Enable CORS (Cross-Origin-Resource-Sharing) request handling.
        /// </summary>
        [Input("cors")]
        public Input<Inputs.DeploymentSpecificationRouteRequestPoliciesCorsGetArgs>? Cors { get; set; }

        /// <summary>
        /// (Updatable) A set of transformations to apply to HTTP headers that pass through the gateway.
        /// </summary>
        [Input("headerTransformations")]
        public Input<Inputs.DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsGetArgs>? HeaderTransformations { get; set; }

        /// <summary>
        /// (Updatable) Validate the HTTP headers on the incoming API requests on a specific route.
        /// </summary>
        [Input("headerValidations")]
        public Input<Inputs.DeploymentSpecificationRouteRequestPoliciesHeaderValidationsGetArgs>? HeaderValidations { get; set; }

        /// <summary>
        /// (Updatable) A set of transformations to apply to query parameters that pass through the gateway.
        /// </summary>
        [Input("queryParameterTransformations")]
        public Input<Inputs.DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsGetArgs>? QueryParameterTransformations { get; set; }

        /// <summary>
        /// (Updatable) Validate the URL query parameters on the incoming API requests on a specific route.
        /// </summary>
        [Input("queryParameterValidations")]
        public Input<Inputs.DeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsGetArgs>? QueryParameterValidations { get; set; }

        /// <summary>
        /// (Updatable) Base policy for Response Cache lookup.
        /// </summary>
        [Input("responseCacheLookup")]
        public Input<Inputs.DeploymentSpecificationRouteRequestPoliciesResponseCacheLookupGetArgs>? ResponseCacheLookup { get; set; }

        public DeploymentSpecificationRouteRequestPoliciesGetArgs()
        {
        }
        public static new DeploymentSpecificationRouteRequestPoliciesGetArgs Empty => new DeploymentSpecificationRouteRequestPoliciesGetArgs();
    }
}
