// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Oda.Outputs
{

    [OutputType]
    public sealed class GetOdaPrivateEndpointScanProxiesOdaPrivateEndpointScanProxyCollectionItemResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ODA Private Endpoint Scan Proxy.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Unique ODA Private Endpoint identifier which is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string OdaPrivateEndpointId;
        /// <summary>
        /// The protocol used for communication between client, scanProxy and RAC's scan listeners
        /// </summary>
        public readonly string Protocol;
        /// <summary>
        /// The FQDN/IPs and port information of customer's Real Application Cluster (RAC)'s SCAN listeners.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOdaPrivateEndpointScanProxiesOdaPrivateEndpointScanProxyCollectionItemScanListenerInfoResult> ScanListenerInfos;
        /// <summary>
        /// Type indicating whether Scan listener is specified by its FQDN or list of IPs
        /// </summary>
        public readonly string ScanListenerType;
        /// <summary>
        /// List only the ODA Private Endpoint Scan Proxies that are in this lifecycle state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// When the resource was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetOdaPrivateEndpointScanProxiesOdaPrivateEndpointScanProxyCollectionItemResult(
            string id,

            string odaPrivateEndpointId,

            string protocol,

            ImmutableArray<Outputs.GetOdaPrivateEndpointScanProxiesOdaPrivateEndpointScanProxyCollectionItemScanListenerInfoResult> scanListenerInfos,

            string scanListenerType,

            string state,

            string timeCreated)
        {
            Id = id;
            OdaPrivateEndpointId = odaPrivateEndpointId;
            Protocol = protocol;
            ScanListenerInfos = scanListenerInfos;
            ScanListenerType = scanListenerType;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}