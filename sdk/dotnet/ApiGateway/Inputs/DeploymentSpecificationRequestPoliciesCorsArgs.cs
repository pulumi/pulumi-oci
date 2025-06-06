// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRequestPoliciesCorsArgs : global::Pulumi.ResourceArgs
    {
        [Input("allowedHeaders")]
        private InputList<string>? _allowedHeaders;

        /// <summary>
        /// (Updatable) The list of headers that will be allowed from the client via the Access-Control-Allow-Headers header. '*' will allow all headers.
        /// </summary>
        public InputList<string> AllowedHeaders
        {
            get => _allowedHeaders ?? (_allowedHeaders = new InputList<string>());
            set => _allowedHeaders = value;
        }

        [Input("allowedMethods")]
        private InputList<string>? _allowedMethods;

        /// <summary>
        /// (Updatable) The list of allowed HTTP methods that will be returned for the preflight OPTIONS request in the Access-Control-Allow-Methods header. '*' will allow all methods.
        /// </summary>
        public InputList<string> AllowedMethods
        {
            get => _allowedMethods ?? (_allowedMethods = new InputList<string>());
            set => _allowedMethods = value;
        }

        [Input("allowedOrigins", required: true)]
        private InputList<string>? _allowedOrigins;

        /// <summary>
        /// (Updatable) The list of allowed origins that the CORS handler will use to respond to CORS requests. The gateway will send the Access-Control-Allow-Origin header with the best origin match for the circumstances. '*' will match any origins, and 'null' will match queries from 'file:' origins. All other origins must be qualified with the scheme, full hostname, and port if necessary.
        /// </summary>
        public InputList<string> AllowedOrigins
        {
            get => _allowedOrigins ?? (_allowedOrigins = new InputList<string>());
            set => _allowedOrigins = value;
        }

        [Input("exposedHeaders")]
        private InputList<string>? _exposedHeaders;

        /// <summary>
        /// (Updatable) The list of headers that the client will be allowed to see from the response as indicated by the Access-Control-Expose-Headers header. '*' will expose all headers.
        /// </summary>
        public InputList<string> ExposedHeaders
        {
            get => _exposedHeaders ?? (_exposedHeaders = new InputList<string>());
            set => _exposedHeaders = value;
        }

        /// <summary>
        /// (Updatable) Whether to send the Access-Control-Allow-Credentials header to allow CORS requests with cookies.
        /// </summary>
        [Input("isAllowCredentialsEnabled")]
        public Input<bool>? IsAllowCredentialsEnabled { get; set; }

        /// <summary>
        /// (Updatable) The time in seconds for the client to cache preflight responses. This is sent as the Access-Control-Max-Age if greater than 0.
        /// </summary>
        [Input("maxAgeInSeconds")]
        public Input<int>? MaxAgeInSeconds { get; set; }

        public DeploymentSpecificationRequestPoliciesCorsArgs()
        {
        }
        public static new DeploymentSpecificationRequestPoliciesCorsArgs Empty => new DeploymentSpecificationRequestPoliciesCorsArgs();
    }
}
