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
    public sealed class DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsSetHeaders
    {
        /// <summary>
        /// (Updatable) The list of headers.
        /// </summary>
        public readonly ImmutableArray<Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsSetHeadersItem> Items;

        [OutputConstructor]
        private DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsSetHeaders(ImmutableArray<Outputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsSetHeadersItem> items)
        {
            Items = items;
        }
    }
}
