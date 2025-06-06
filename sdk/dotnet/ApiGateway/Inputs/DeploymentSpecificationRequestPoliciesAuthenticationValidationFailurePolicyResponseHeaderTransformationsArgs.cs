// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
        /// </summary>
        [Input("filterHeaders")]
        public Input<Inputs.DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsFilterHeadersArgs>? FilterHeaders { get; set; }

        /// <summary>
        /// (Updatable) Rename HTTP headers as they pass through the gateway.
        /// </summary>
        [Input("renameHeaders")]
        public Input<Inputs.DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersArgs>? RenameHeaders { get; set; }

        /// <summary>
        /// (Updatable) Set HTTP headers as they pass through the gateway.
        /// </summary>
        [Input("setHeaders")]
        public Input<Inputs.DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsSetHeadersArgs>? SetHeaders { get; set; }

        public DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsArgs()
        {
        }
        public static new DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsArgs Empty => new DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsArgs();
    }
}
