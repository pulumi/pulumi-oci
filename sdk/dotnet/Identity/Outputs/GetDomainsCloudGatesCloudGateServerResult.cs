// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetDomainsCloudGatesCloudGateServerResult
    {
        /// <summary>
        /// Any incoming request to cloud gate is finally sent to this host, if selected during load balancing
        /// </summary>
        public readonly string HostName;
        /// <summary>
        /// Any additional settings for this upstream server in nginx configuration form
        /// </summary>
        public readonly string NginxSettings;
        /// <summary>
        /// Port for the Upstream Server
        /// </summary>
        public readonly int Port;
        /// <summary>
        /// Server Name for the Server Block
        /// </summary>
        public readonly string ServerId;
        /// <summary>
        /// SSL flag for the Upstream Block
        /// </summary>
        public readonly bool Ssl;

        [OutputConstructor]
        private GetDomainsCloudGatesCloudGateServerResult(
            string hostName,

            string nginxSettings,

            int port,

            string serverId,

            bool ssl)
        {
            HostName = hostName;
            NginxSettings = nginxSettings;
            Port = port;
            ServerId = serverId;
            Ssl = ssl;
        }
    }
}
