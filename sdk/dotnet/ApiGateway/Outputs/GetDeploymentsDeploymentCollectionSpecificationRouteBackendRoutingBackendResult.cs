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
    public sealed class GetDeploymentsDeploymentCollectionSpecificationRouteBackendRoutingBackendResult
    {
        /// <summary>
        /// The backend to forward requests to.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRouteBackendRoutingBackendBackendResult> Backends;
        /// <summary>
        /// Information around the values for selector of an authentication/ routing branch.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRouteBackendRoutingBackendKeyResult> Keys;

        [OutputConstructor]
        private GetDeploymentsDeploymentCollectionSpecificationRouteBackendRoutingBackendResult(
            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRouteBackendRoutingBackendBackendResult> backends,

            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRouteBackendRoutingBackendKeyResult> keys)
        {
            Backends = backends;
            Keys = keys;
        }
    }
}
