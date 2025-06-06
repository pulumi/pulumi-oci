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
    public sealed class GetDeploymentSpecificationRouteBackendRoutingBackendResult
    {
        /// <summary>
        /// The backend to forward requests to.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRouteBackendRoutingBackendBackendResult> Backends;
        /// <summary>
        /// Information around the values for selector of an authentication/ routing branch.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentSpecificationRouteBackendRoutingBackendKeyResult> Keys;

        [OutputConstructor]
        private GetDeploymentSpecificationRouteBackendRoutingBackendResult(
            ImmutableArray<Outputs.GetDeploymentSpecificationRouteBackendRoutingBackendBackendResult> backends,

            ImmutableArray<Outputs.GetDeploymentSpecificationRouteBackendRoutingBackendKeyResult> keys)
        {
            Backends = backends;
            Keys = keys;
        }
    }
}
