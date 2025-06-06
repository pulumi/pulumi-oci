// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs : global::Pulumi.ResourceArgs
    {
        [Input("items", required: true)]
        private InputList<Inputs.DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItemArgs>? _items;

        /// <summary>
        /// (Updatable) The list of headers.
        /// </summary>
        public InputList<Inputs.DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItemArgs> Items
        {
            get => _items ?? (_items = new InputList<Inputs.DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItemArgs>());
            set => _items = value;
        }

        /// <summary>
        /// (Updatable) BLOCK drops any headers that are in the list of items, so it acts as an exclusion list.  ALLOW permits only the headers in the list and removes all others, so it acts as an inclusion list.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs()
        {
        }
        public static new DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs Empty => new DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs();
    }
}
