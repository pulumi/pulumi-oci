// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waf.Inputs
{

    public sealed class AppFirewallPolicyActionGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Type of returned HTTP response body.
        /// </summary>
        [Input("body")]
        public Input<Inputs.AppFirewallPolicyActionBodyGetArgs>? Body { get; set; }

        /// <summary>
        /// (Updatable) Response code.
        /// 
        /// The following response codes are valid values for this property:
        /// * 2xx
        /// 
        /// 200 OK 201 Created 202 Accepted 206 Partial Content
        /// * 3xx
        /// 
        /// 300 Multiple Choices 301 Moved Permanently 302 Found 303 See Other 307 Temporary Redirect
        /// * 4xx
        /// 
        /// 400 Bad Request 401 Unauthorized 403 Forbidden 404 Not Found 405 Method Not Allowed 408 Request Timeout 409 Conflict 411 Length Required 412 Precondition Failed 413 Payload Too Large 414 URI Too Long 415 Unsupported Media Type 416 Range Not Satisfiable 422 Unprocessable Entity 494 Request Header Too Large 495 Cert Error 496 No Cert 497 HTTP to HTTPS
        /// * 5xx
        /// 
        /// 500 Internal Server Error 501 Not Implemented 502 Bad Gateway 503 Service Unavailable 504 Gateway Timeout 507 Insufficient Storage
        /// 
        /// Example: `200`
        /// </summary>
        [Input("code")]
        public Input<int>? Code { get; set; }

        [Input("headers")]
        private InputList<Inputs.AppFirewallPolicyActionHeaderGetArgs>? _headers;

        /// <summary>
        /// (Updatable) Adds headers defined in this array for HTTP response.
        /// 
        /// Hop-by-hop headers are not allowed to be set:
        /// * Connection
        /// * Keep-Alive
        /// * Proxy-Authenticate
        /// * Proxy-Authorization
        /// * TE
        /// * Trailer
        /// * Transfer-Encoding
        /// * Upgrade
        /// </summary>
        public InputList<Inputs.AppFirewallPolicyActionHeaderGetArgs> Headers
        {
            get => _headers ?? (_headers = new InputList<Inputs.AppFirewallPolicyActionHeaderGetArgs>());
            set => _headers = value;
        }

        /// <summary>
        /// (Updatable) Action name. Can be used to reference the action.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        /// <summary>
        /// (Updatable) 
        /// * **CHECK** is a non-terminating action that does not stop the execution of rules in current module, just emits a log message documenting result of rule execution.
        /// * **ALLOW** is a non-terminating action which upon matching rule skips all remaining rules in the current module.
        /// * **RETURN_HTTP_RESPONSE** is a terminating action which is executed immediately, returns a defined HTTP response.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public AppFirewallPolicyActionGetArgs()
        {
        }
        public static new AppFirewallPolicyActionGetArgs Empty => new AppFirewallPolicyActionGetArgs();
    }
}
