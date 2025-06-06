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
    public sealed class GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidationResult
    {
        public readonly ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidationHeaderResult> Headers;
        /// <summary>
        /// Validation behavior mode.
        /// </summary>
        public readonly string ValidationMode;

        [OutputConstructor]
        private GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidationResult(
            ImmutableArray<Outputs.GetApiDeploymentSpecificationRouteRequestPolicyHeaderValidationHeaderResult> headers,

            string validationMode)
        {
            Headers = headers;
            ValidationMode = validationMode;
        }
    }
}
