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
    public sealed class GetDeploymentsDeploymentCollectionSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationResult
    {
        /// <summary>
        /// Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationFilterHeaderResult> FilterHeaders;
        /// <summary>
        /// Rename HTTP headers as they pass through the gateway.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeaderResult> RenameHeaders;
        /// <summary>
        /// Set HTTP headers as they pass through the gateway.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeaderResult> SetHeaders;

        [OutputConstructor]
        private GetDeploymentsDeploymentCollectionSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationResult(
            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationFilterHeaderResult> filterHeaders,

            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationRenameHeaderResult> renameHeaders,

            ImmutableArray<Outputs.GetDeploymentsDeploymentCollectionSpecificationRequestPolicyAuthenticationValidationFailurePolicyResponseHeaderTransformationSetHeaderResult> setHeaders)
        {
            FilterHeaders = filterHeaders;
            RenameHeaders = renameHeaders;
            SetHeaders = setHeaders;
        }
    }
}