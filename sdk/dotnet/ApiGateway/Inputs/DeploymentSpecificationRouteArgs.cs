// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRouteArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The backend to forward requests to.
        /// </summary>
        [Input("backend", required: true)]
        public Input<Inputs.DeploymentSpecificationRouteBackendArgs> Backend { get; set; } = null!;

        /// <summary>
        /// (Updatable) Policies controlling the pushing of logs to Oracle Cloud Infrastructure Public Logging.
        /// </summary>
        [Input("loggingPolicies")]
        public Input<Inputs.DeploymentSpecificationRouteLoggingPoliciesArgs>? LoggingPolicies { get; set; }

        [Input("methods")]
        private InputList<string>? _methods;

        /// <summary>
        /// (Updatable) A list of allowed methods on this route.
        /// </summary>
        public InputList<string> Methods
        {
            get => _methods ?? (_methods = new InputList<string>());
            set => _methods = value;
        }

        /// <summary>
        /// (Updatable) A URL path pattern that must be matched on this route. The path pattern may contain a subset of RFC 6570 identifiers to allow wildcard and parameterized matching.
        /// </summary>
        [Input("path", required: true)]
        public Input<string> Path { get; set; } = null!;

        /// <summary>
        /// (Updatable) Behavior applied to any requests received by the API on this route.
        /// </summary>
        [Input("requestPolicies")]
        public Input<Inputs.DeploymentSpecificationRouteRequestPoliciesArgs>? RequestPolicies { get; set; }

        /// <summary>
        /// (Updatable) Behavior applied to any responses sent by the API for requests on this route.
        /// </summary>
        [Input("responsePolicies")]
        public Input<Inputs.DeploymentSpecificationRouteResponsePoliciesArgs>? ResponsePolicies { get; set; }

        public DeploymentSpecificationRouteArgs()
        {
        }
        public static new DeploymentSpecificationRouteArgs Empty => new DeploymentSpecificationRouteArgs();
    }
}
