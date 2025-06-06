// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Oda.Outputs
{

    [OutputType]
    public sealed class OdaPrivateEndpointScanProxyScanListenerInfo
    {
        /// <summary>
        /// FQDN of the customer's Real Application Cluster (RAC)'s SCAN listeners.
        /// </summary>
        public readonly string? ScanListenerFqdn;
        /// <summary>
        /// A SCAN listener's IP of the customer's Real Application Cluster (RAC).
        /// </summary>
        public readonly string? ScanListenerIp;
        /// <summary>
        /// The port that customer's Real Application Cluster (RAC)'s SCAN listeners are listening on.
        /// </summary>
        public readonly int? ScanListenerPort;

        [OutputConstructor]
        private OdaPrivateEndpointScanProxyScanListenerInfo(
            string? scanListenerFqdn,

            string? scanListenerIp,

            int? scanListenerPort)
        {
            ScanListenerFqdn = scanListenerFqdn;
            ScanListenerIp = scanListenerIp;
            ScanListenerPort = scanListenerPort;
        }
    }
}
