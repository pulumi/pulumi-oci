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
    public sealed class GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationResult
    {
        /// <summary>
        /// List of authentication servers to choose from during dynamic authentication.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerResult> AuthenticationServers;
        /// <summary>
        /// Information around selector used for branching among routes/ authentication servers while dynamic routing/ authentication.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationSelectionSourceResult> SelectionSources;

        [OutputConstructor]
        private GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationResult(
            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationAuthenticationServerResult> authenticationServers,

            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRequestPolicyDynamicAuthenticationSelectionSourceResult> selectionSources)
        {
            AuthenticationServers = authenticationServers;
            SelectionSources = selectionSources;
        }
    }
}