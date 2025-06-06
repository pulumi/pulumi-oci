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
    public sealed class DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyAdditionalValidationPolicy
    {
        /// <summary>
        /// (Updatable) The list of intended recipients for the token.
        /// </summary>
        public readonly ImmutableArray<string> Audiences;
        /// <summary>
        /// (Updatable) A list of parties that could have issued the token.
        /// </summary>
        public readonly ImmutableArray<string> Issuers;
        /// <summary>
        /// (Updatable) A list of claims which should be validated to consider the token valid.
        /// </summary>
        public readonly ImmutableArray<Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyAdditionalValidationPolicyVerifyClaim> VerifyClaims;

        [OutputConstructor]
        private DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyAdditionalValidationPolicy(
            ImmutableArray<string> audiences,

            ImmutableArray<string> issuers,

            ImmutableArray<Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicyAdditionalValidationPolicyVerifyClaim> verifyClaims)
        {
            Audiences = audiences;
            Issuers = issuers;
            VerifyClaims = verifyClaims;
        }
    }
}
