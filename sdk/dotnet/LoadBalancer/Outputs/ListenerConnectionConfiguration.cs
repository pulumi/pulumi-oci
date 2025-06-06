// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Outputs
{

    [OutputType]
    public sealed class ListenerConnectionConfiguration
    {
        /// <summary>
        /// (Updatable) An array that represents the PPV2 Options that can be enabled on TCP Listeners. Example: ["PP2_TYPE_AUTHORITY"]
        /// </summary>
        public readonly ImmutableArray<string> BackendTcpProxyProtocolOptions;
        /// <summary>
        /// (Updatable) The backend TCP Proxy Protocol version.  Example: `1`
        /// </summary>
        public readonly int? BackendTcpProxyProtocolVersion;
        /// <summary>
        /// (Updatable) The maximum idle time, in seconds, allowed between two successive receive or two successive send operations between the client and backend servers. A send operation does not reset the timer for receive operations. A receive operation does not reset the timer for send operations.
        /// 
        /// For more information, see [Connection Configuration](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/connectionreuse.htm#ConnectionConfiguration).
        /// 
        /// Example: `1200`
        /// </summary>
        public readonly string IdleTimeoutInSeconds;

        [OutputConstructor]
        private ListenerConnectionConfiguration(
            ImmutableArray<string> backendTcpProxyProtocolOptions,

            int? backendTcpProxyProtocolVersion,

            string idleTimeoutInSeconds)
        {
            BackendTcpProxyProtocolOptions = backendTcpProxyProtocolOptions;
            BackendTcpProxyProtocolVersion = backendTcpProxyProtocolVersion;
            IdleTimeoutInSeconds = idleTimeoutInSeconds;
        }
    }
}
