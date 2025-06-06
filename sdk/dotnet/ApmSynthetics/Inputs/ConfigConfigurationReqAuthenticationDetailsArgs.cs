// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Inputs
{

    public sealed class ConfigConfigurationReqAuthenticationDetailsArgs : global::Pulumi.ResourceArgs
    {
        [Input("authHeaders")]
        private InputList<Inputs.ConfigConfigurationReqAuthenticationDetailsAuthHeaderArgs>? _authHeaders;

        /// <summary>
        /// (Updatable) List of authentication headers. Example: `[{"headerName": "content-type", "headerValue":"json"}]`
        /// </summary>
        public InputList<Inputs.ConfigConfigurationReqAuthenticationDetailsAuthHeaderArgs> AuthHeaders
        {
            get => _authHeaders ?? (_authHeaders = new InputList<Inputs.ConfigConfigurationReqAuthenticationDetailsAuthHeaderArgs>());
            set => _authHeaders = value;
        }

        /// <summary>
        /// (Updatable) Request method.
        /// </summary>
        [Input("authRequestMethod")]
        public Input<string>? AuthRequestMethod { get; set; }

        /// <summary>
        /// (Updatable) Request post body.
        /// </summary>
        [Input("authRequestPostBody")]
        public Input<string>? AuthRequestPostBody { get; set; }

        /// <summary>
        /// (Updatable) Authentication token.
        /// </summary>
        [Input("authToken")]
        public Input<string>? AuthToken { get; set; }

        /// <summary>
        /// (Updatable) URL to get authentication token.
        /// </summary>
        [Input("authUrl")]
        public Input<string>? AuthUrl { get; set; }

        /// <summary>
        /// (Updatable) User name for authentication.
        /// </summary>
        [Input("authUserName")]
        public Input<string>? AuthUserName { get; set; }

        [Input("authUserPassword")]
        private Input<string>? _authUserPassword;

        /// <summary>
        /// (Updatable) User password for authentication.
        /// </summary>
        public Input<string>? AuthUserPassword
        {
            get => _authUserPassword;
            set
            {
                var emptySecret = Output.CreateSecret(0);
                _authUserPassword = Output.Tuple<Input<string>?, int>(value, emptySecret).Apply(t => t.Item1);
            }
        }

        /// <summary>
        /// (Updatable) Request HTTP OAuth scheme.
        /// </summary>
        [Input("oauthScheme")]
        public Input<string>? OauthScheme { get; set; }

        public ConfigConfigurationReqAuthenticationDetailsArgs()
        {
        }
        public static new ConfigConfigurationReqAuthenticationDetailsArgs Empty => new ConfigConfigurationReqAuthenticationDetailsArgs();
    }
}
