// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRouteBackendSelectionSourceGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) String describing the context variable used as selector.
        /// </summary>
        [Input("selector", required: true)]
        public Input<string> Selector { get; set; } = null!;

        /// <summary>
        /// (Updatable) Type of the Selection source to use.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public DeploymentSpecificationRouteBackendSelectionSourceGetArgs()
        {
        }
        public static new DeploymentSpecificationRouteBackendSelectionSourceGetArgs Empty => new DeploymentSpecificationRouteBackendSelectionSourceGetArgs();
    }
}
