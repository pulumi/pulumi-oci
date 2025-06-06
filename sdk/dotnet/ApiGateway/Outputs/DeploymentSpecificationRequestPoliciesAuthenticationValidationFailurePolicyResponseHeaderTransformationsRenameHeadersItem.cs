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
    public sealed class DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersItem
    {
        /// <summary>
        /// (Updatable) The original case-insensitive name of the header.  This name must be unique across transformation policies.
        /// </summary>
        public readonly string? From;
        /// <summary>
        /// (Updatable) The new name of the header.  This name must be unique across transformation policies.
        /// </summary>
        public readonly string? To;

        [OutputConstructor]
        private DeploymentSpecificationRequestPoliciesAuthenticationValidationFailurePolicyResponseHeaderTransformationsRenameHeadersItem(
            string? from,

            string? to)
        {
            From = from;
            To = to;
        }
    }
}
