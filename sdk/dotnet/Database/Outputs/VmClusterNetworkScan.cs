// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class VmClusterNetworkScan
    {
        /// <summary>
        /// (Updatable) The node host name.
        /// </summary>
        public readonly string Hostname;
        /// <summary>
        /// (Updatable) The list of SCAN IP addresses. Three addresses should be provided.
        /// </summary>
        public readonly ImmutableArray<string> Ips;
        /// <summary>
        /// (Updatable) The SCAN TCPIP port. Default is 1521.
        /// </summary>
        public readonly int Port;
        /// <summary>
        /// (Updatable) The SCAN TCPIP port. Default is 1521.
        /// </summary>
        public readonly int? ScanListenerPortTcp;
        /// <summary>
        /// (Updatable) The SCAN TCPIP SSL port. Default is 2484.
        /// </summary>
        public readonly int? ScanListenerPortTcpSsl;

        [OutputConstructor]
        private VmClusterNetworkScan(
            string hostname,

            ImmutableArray<string> ips,

            int port,

            int? scanListenerPortTcp,

            int? scanListenerPortTcpSsl)
        {
            Hostname = hostname;
            Ips = ips;
            Port = port;
            ScanListenerPortTcp = scanListenerPortTcp;
            ScanListenerPortTcpSsl = scanListenerPortTcpSsl;
        }
    }
}