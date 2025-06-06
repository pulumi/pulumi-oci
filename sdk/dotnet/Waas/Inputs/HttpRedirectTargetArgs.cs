// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Inputs
{

    public sealed class HttpRedirectTargetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The host portion of the redirect.
        /// </summary>
        [Input("host", required: true)]
        public Input<string> Host { get; set; } = null!;

        /// <summary>
        /// (Updatable) The path component of the target URL (e.g., "/path/to/resource" in "https://target.example.com/path/to/resource?redirected"), which can be empty, static, or request-copying, or request-prefixing. Use of \ is not permitted except to escape a following \, {, or }. An empty value is treated the same as static "/". A static value must begin with a leading "/", optionally followed by other path characters. A request-copying value must exactly match "{path}", and will be replaced with the path component of the request URL (including its initial "/"). A request-prefixing value must start with "/" and end with a non-escaped "{path}", which will be replaced with the path component of the request URL (including its initial "/"). Only one such replacement token is allowed.
        /// </summary>
        [Input("path", required: true)]
        public Input<string> Path { get; set; } = null!;

        /// <summary>
        /// (Updatable) Port number of the target destination of the redirect, default to match protocol
        /// </summary>
        [Input("port")]
        public Input<int>? Port { get; set; }

        /// <summary>
        /// (Updatable) The protocol used for the target, http or https.
        /// </summary>
        [Input("protocol", required: true)]
        public Input<string> Protocol { get; set; } = null!;

        /// <summary>
        /// (Updatable) The query component of the target URL (e.g., "?redirected" in "https://target.example.com/path/to/resource?redirected"), which can be empty, static, or request-copying. Use of \ is not permitted except to escape a following \, {, or }. An empty value results in a redirection target URL with no query component. A static value must begin with a leading "?", optionally followed by other query characters. A request-copying value must exactly match "{query}", and will be replaced with the query component of the request URL (including a leading "?" if and only if the request URL includes a query component).
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("query", required: true)]
        public Input<string> Query { get; set; } = null!;

        public HttpRedirectTargetArgs()
        {
        }
        public static new HttpRedirectTargetArgs Empty => new HttpRedirectTargetArgs();
    }
}
