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
    public sealed class GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidationResult
    {
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidationHeaderResult> Headers;
        /// <summary>
        /// Validation behavior mode.
        /// </summary>
        public readonly string ValidationMode;

        [OutputConstructor]
        private GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidationResult(
            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyHeaderValidationHeaderResult> headers,

            string validationMode)
        {
            Headers = headers;
            ValidationMode = validationMode;
        }
    }
}
