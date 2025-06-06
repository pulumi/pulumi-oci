// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRouteBackendRoutingBackendBackendArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The body of the stock response from the mock backend.
        /// </summary>
        [Input("body")]
        public Input<string>? Body { get; set; }

        /// <summary>
        /// Defines a timeout for establishing a connection with a proxied server.
        /// </summary>
        [Input("connectTimeoutInSeconds")]
        public Input<double>? ConnectTimeoutInSeconds { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Functions function resource.
        /// </summary>
        [Input("functionId")]
        public Input<string>? FunctionId { get; set; }

        [Input("headers")]
        private InputList<Inputs.DeploymentSpecificationRouteBackendRoutingBackendBackendHeaderArgs>? _headers;
        public InputList<Inputs.DeploymentSpecificationRouteBackendRoutingBackendBackendHeaderArgs> Headers
        {
            get => _headers ?? (_headers = new InputList<Inputs.DeploymentSpecificationRouteBackendRoutingBackendBackendHeaderArgs>());
            set => _headers = value;
        }

        /// <summary>
        /// Defines whether or not to uphold SSL verification.
        /// </summary>
        [Input("isSslVerifyDisabled")]
        public Input<bool>? IsSslVerifyDisabled { get; set; }

        /// <summary>
        /// Defines a timeout for reading a response from the proxied server.
        /// </summary>
        [Input("readTimeoutInSeconds")]
        public Input<double>? ReadTimeoutInSeconds { get; set; }

        /// <summary>
        /// Defines a timeout for transmitting a request to the proxied server.
        /// </summary>
        [Input("sendTimeoutInSeconds")]
        public Input<double>? SendTimeoutInSeconds { get; set; }

        /// <summary>
        /// The status code of the stock response from the mock backend.
        /// </summary>
        [Input("status")]
        public Input<int>? Status { get; set; }

        /// <summary>
        /// Type of the Response Cache Store Policy.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        [Input("url")]
        public Input<string>? Url { get; set; }

        public DeploymentSpecificationRouteBackendRoutingBackendBackendArgs()
        {
        }
        public static new DeploymentSpecificationRouteBackendRoutingBackendBackendArgs Empty => new DeploymentSpecificationRouteBackendRoutingBackendBackendArgs();
    }
}
