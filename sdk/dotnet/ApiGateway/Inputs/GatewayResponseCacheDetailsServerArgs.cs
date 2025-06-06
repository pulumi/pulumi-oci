// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class GatewayResponseCacheDetailsServerArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Hostname or IP address (IPv4 only) where the cache store is running.
        /// </summary>
        [Input("host")]
        public Input<string>? Host { get; set; }

        /// <summary>
        /// (Updatable) The port the cache store is exposed on.
        /// </summary>
        [Input("port")]
        public Input<int>? Port { get; set; }

        public GatewayResponseCacheDetailsServerArgs()
        {
        }
        public static new GatewayResponseCacheDetailsServerArgs Empty => new GatewayResponseCacheDetailsServerArgs();
    }
}
