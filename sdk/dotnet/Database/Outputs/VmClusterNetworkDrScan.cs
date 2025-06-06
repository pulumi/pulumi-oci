// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class VmClusterNetworkDrScan
    {
        /// <summary>
        /// (Updatable) The Disaster recovery SCAN hostname.
        /// </summary>
        public readonly string Hostname;
        /// <summary>
        /// (Updatable) The list of Disaster recovery SCAN IP addresses. Three addresses should be provided.
        /// </summary>
        public readonly ImmutableArray<string> Ips;
        /// <summary>
        /// (Updatable) The Disaster recovery SCAN TCPIP port. Default is 1521.
        /// </summary>
        public readonly int ScanListenerPortTcp;

        [OutputConstructor]
        private VmClusterNetworkDrScan(
            string hostname,

            ImmutableArray<string> ips,

            int scanListenerPortTcp)
        {
            Hostname = hostname;
            Ips = ips;
            ScanListenerPortTcp = scanListenerPortTcp;
        }
    }
}
