// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsRenameHeadersGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("items")]
        private InputList<Inputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsRenameHeadersItemGetArgs>? _items;

        /// <summary>
        /// (Updatable) The list of headers.
        /// </summary>
        public InputList<Inputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsRenameHeadersItemGetArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsRenameHeadersItemGetArgs>());
            set => _items = value;
        }

        public DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsRenameHeadersGetArgs()
        {
        }
        public static new DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsRenameHeadersGetArgs Empty => new DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationFailurePolicyResponseHeaderTransformationsRenameHeadersGetArgs();
    }
}
