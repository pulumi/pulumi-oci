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
    public sealed class GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationResult
    {
        /// <summary>
        /// Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationFilterHeaderResult> FilterHeaders;
        /// <summary>
        /// Rename HTTP headers as they pass through the gateway.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationRenameHeaderResult> RenameHeaders;
        /// <summary>
        /// Set HTTP headers as they pass through the gateway.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationSetHeaderResult> SetHeaders;

        [OutputConstructor]
        private GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationResult(
            ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationFilterHeaderResult> filterHeaders,

            ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationRenameHeaderResult> renameHeaders,

            ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteResponsePolicyHeaderTransformationSetHeaderResult> setHeaders)
        {
            FilterHeaders = filterHeaders;
            RenameHeaders = renameHeaders;
            SetHeaders = setHeaders;
        }
    }
}