// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Outputs
{

    [OutputType]
    public sealed class GetWaasPoliciesWaasPolicyOriginResult
    {
        /// <summary>
        /// A list of HTTP headers to forward to your origin.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWaasPoliciesWaasPolicyOriginCustomHeaderResult> CustomHeaders;
        /// <summary>
        /// The HTTP port on the origin that the web application listens on. If unspecified, defaults to `80`. If `0` is specified - the origin is not used for HTTP traffic.
        /// </summary>
        public readonly int HttpPort;
        /// <summary>
        /// The HTTPS port on the origin that the web application listens on. If unspecified, defaults to `443`. If `0` is specified - the origin is not used for HTTPS traffic.
        /// </summary>
        public readonly int HttpsPort;
        public readonly string Label;
        /// <summary>
        /// The URI of the origin. Does not support paths. Port numbers should be specified in the `httpPort` and `httpsPort` fields.
        /// </summary>
        public readonly string Uri;

        [OutputConstructor]
        private GetWaasPoliciesWaasPolicyOriginResult(
            ImmutableArray<Outputs.GetWaasPoliciesWaasPolicyOriginCustomHeaderResult> customHeaders,

            int httpPort,

            int httpsPort,

            string label,

            string uri)
        {
            CustomHeaders = customHeaders;
            HttpPort = httpPort;
            HttpsPort = httpsPort;
            Label = label;
            Uri = uri;
        }
    }
}
