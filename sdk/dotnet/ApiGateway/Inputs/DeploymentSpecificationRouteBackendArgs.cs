// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRouteBackendArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The body of the stock response from the mock backend.
        /// </summary>
        [Input("body")]
        public Input<string>? Body { get; set; }

        /// <summary>
        /// (Updatable) Defines a timeout for establishing a connection with a proxied server.
        /// </summary>
        [Input("connectTimeoutInSeconds")]
        public Input<double>? ConnectTimeoutInSeconds { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Functions function resource.
        /// </summary>
        [Input("functionId")]
        public Input<string>? FunctionId { get; set; }

        [Input("headers")]
        private InputList<Inputs.DeploymentSpecificationRouteBackendHeaderArgs>? _headers;

        /// <summary>
        /// (Updatable)
        /// </summary>
        public InputList<Inputs.DeploymentSpecificationRouteBackendHeaderArgs> Headers
        {
            get => _headers ?? (_headers = new InputList<Inputs.DeploymentSpecificationRouteBackendHeaderArgs>());
            set => _headers = value;
        }

        /// <summary>
        /// (Updatable) Defines whether or not to uphold SSL verification.
        /// </summary>
        [Input("isSslVerifyDisabled")]
        public Input<bool>? IsSslVerifyDisabled { get; set; }

        /// <summary>
        /// (Updatable) Defines a timeout for reading a response from the proxied server.
        /// </summary>
        [Input("readTimeoutInSeconds")]
        public Input<double>? ReadTimeoutInSeconds { get; set; }

        /// <summary>
        /// (Updatable) Defines a timeout for transmitting a request to the proxied server.
        /// </summary>
        [Input("sendTimeoutInSeconds")]
        public Input<double>? SendTimeoutInSeconds { get; set; }

        /// <summary>
        /// (Updatable) The status code of the stock response from the mock backend.
        /// </summary>
        [Input("status")]
        public Input<int>? Status { get; set; }

        /// <summary>
        /// (Updatable) Type of the Response Cache Store Policy.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        /// <summary>
        /// (Updatable)
        /// </summary>
        [Input("url")]
        public Input<string>? Url { get; set; }

        public DeploymentSpecificationRouteBackendArgs()
        {
        }
        public static new DeploymentSpecificationRouteBackendArgs Empty => new DeploymentSpecificationRouteBackendArgs();
    }
}