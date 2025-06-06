// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRouteBackendHeaderGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Name of the header.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) Value of the header.
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public DeploymentSpecificationRouteBackendHeaderGetArgs()
        {
        }
        public static new DeploymentSpecificationRouteBackendHeaderGetArgs Empty => new DeploymentSpecificationRouteBackendHeaderGetArgs();
    }
}
