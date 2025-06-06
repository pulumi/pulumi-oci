// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Inputs
{

    public sealed class PolicyPolicyConfigArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the SSL certificate to use if HTTPS is supported.
        /// </summary>
        [Input("certificateId")]
        public Input<string>? CertificateId { get; set; }

        /// <summary>
        /// (Updatable) The set cipher group for the configured TLS protocol. This sets the configuration for the TLS connections between clients and edge nodes only.
        /// * **DEFAULT:** Cipher group supports TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3 protocols. It has the following ciphers enabled: `ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:!DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA`
        /// </summary>
        [Input("cipherGroup")]
        public Input<string>? CipherGroup { get; set; }

        /// <summary>
        /// (Updatable) Specifies an HTTP header name which is treated as the connecting client's IP address. Applicable only if `isBehindCdn` is enabled.
        /// 
        /// The edge node reads this header and its value and sets the client IP address as specified. It does not create the header if the header is not present in the request. If the header is not present, the connecting IP address will be used as the client's true IP address. It uses the last IP address in the header's value as the true IP address.
        /// 
        /// Example: `X-Client-Ip: 11.1.1.1, 13.3.3.3`
        /// 
        /// In the case of multiple headers with the same name, only the first header will be used. It is assumed that CDN sets the correct client IP address to prevent spoofing.
        /// * **X_FORWARDED_FOR:** Corresponds to `X-Forwarded-For` header name.
        /// * **X_CLIENT_IP:** Corresponds to `X-Client-Ip` header name.
        /// * **X_REAL_IP:** Corresponds to `X-Real-Ip` header name.
        /// * **CLIENT_IP:** Corresponds to `Client-Ip` header name.
        /// * **TRUE_CLIENT_IP:** Corresponds to `True-Client-Ip` header name.
        /// </summary>
        [Input("clientAddressHeader")]
        public Input<string>? ClientAddressHeader { get; set; }

        /// <summary>
        /// (Updatable) Health checks monitor the status of your origin servers and only route traffic to the origins that pass the health check. If the health check fails, origin is automatically removed from the load balancing. There is roughly one health check per EDGE POP per period. Any checks that pass will be reported as "healthy".
        /// </summary>
        [Input("healthChecks")]
        public Input<Inputs.PolicyPolicyConfigHealthChecksArgs>? HealthChecks { get; set; }

        /// <summary>
        /// (Updatable) Enabling `isBehindCdn` allows for the collection of IP addresses from client requests if the WAF is connected to a CDN.
        /// </summary>
        [Input("isBehindCdn")]
        public Input<bool>? IsBehindCdn { get; set; }

        /// <summary>
        /// (Updatable) Enable or disable automatic content caching based on the response `cache-control` header. This feature enables the origin to act as a proxy cache. Caching is usually defined using `cache-control` header. For example `cache-control: max-age=120` means that the returned resource is valid for 120 seconds. Caching rules will overwrite this setting.
        /// </summary>
        [Input("isCacheControlRespected")]
        public Input<bool>? IsCacheControlRespected { get; set; }

        /// <summary>
        /// (Updatable) Enable or disable HTTPS support. If true, a `certificateId` is required. If unspecified, defaults to `false`.
        /// </summary>
        [Input("isHttpsEnabled")]
        public Input<bool>? IsHttpsEnabled { get; set; }

        /// <summary>
        /// (Updatable) Force HTTP to HTTPS redirection. If unspecified, defaults to `false`.
        /// </summary>
        [Input("isHttpsForced")]
        public Input<bool>? IsHttpsForced { get; set; }

        /// <summary>
        /// (Updatable) Enable or disable GZIP compression of origin responses. If enabled, the header `Accept-Encoding: gzip` is sent to origin, otherwise, the empty `Accept-Encoding:` header is used.
        /// </summary>
        [Input("isOriginCompressionEnabled")]
        public Input<bool>? IsOriginCompressionEnabled { get; set; }

        /// <summary>
        /// (Updatable) Enable or disable buffering of responses from the origin. Buffering improves overall stability in case of network issues, but slightly increases Time To First Byte.
        /// </summary>
        [Input("isResponseBufferingEnabled")]
        public Input<bool>? IsResponseBufferingEnabled { get; set; }

        /// <summary>
        /// (Updatable) SNI stands for Server Name Indication and is an extension of the TLS protocol. It indicates which hostname is being contacted by the browser at the beginning of the 'handshake'-process. This allows a server to connect multiple SSL Certificates to one IP address and port.
        /// </summary>
        [Input("isSniEnabled")]
        public Input<bool>? IsSniEnabled { get; set; }

        /// <summary>
        /// (Updatable) An object that represents a load balancing method and its properties.
        /// </summary>
        [Input("loadBalancingMethod")]
        public Input<Inputs.PolicyPolicyConfigLoadBalancingMethodArgs>? LoadBalancingMethod { get; set; }

        [Input("tlsProtocols")]
        private InputList<string>? _tlsProtocols;

        /// <summary>
        /// (Updatable) A list of allowed TLS protocols. Only applicable when HTTPS support is enabled. The TLS protocol is negotiated while the request is connecting and the most recent protocol supported by both the edge node and client browser will be selected. If no such version exists, the connection will be aborted.
        /// * **TLS_V1:** corresponds to TLS 1.0 specification.
        /// * **TLS_V1_1:** corresponds to TLS 1.1 specification.
        /// * **TLS_V1_2:** corresponds to TLS 1.2 specification.
        /// * **TLS_V1_3:** corresponds to TLS 1.3 specification.
        /// 
        /// Enabled TLS protocols must go in a row. For example if `TLS_v1_1` and `TLS_V1_3` are enabled, `TLS_V1_2` must be enabled too.
        /// </summary>
        public InputList<string> TlsProtocols
        {
            get => _tlsProtocols ?? (_tlsProtocols = new InputList<string>());
            set => _tlsProtocols = value;
        }

        [Input("websocketPathPrefixes")]
        private InputList<string>? _websocketPathPrefixes;

        /// <summary>
        /// (Updatable) ModSecurity is not capable to inspect WebSockets. Therefore paths specified here have WAF disabled if Connection request header from the client has the value Upgrade (case insensitive matching) and Upgrade request header has the value websocket (case insensitive matching). Paths matches if the concatenation of request URL path and query starts with the contents of the one of `websocketPathPrefixes` array value. In All other cases challenges, like JSC, HIC and etc., remain active.
        /// </summary>
        public InputList<string> WebsocketPathPrefixes
        {
            get => _websocketPathPrefixes ?? (_websocketPathPrefixes = new InputList<string>());
            set => _websocketPathPrefixes = value;
        }

        public PolicyPolicyConfigArgs()
        {
        }
        public static new PolicyPolicyConfigArgs Empty => new PolicyPolicyConfigArgs();
    }
}
