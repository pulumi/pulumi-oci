// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class DrgAttachmentNetworkDetails
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network attached to the DRG.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The IPSec connection that contains the attached IPSec tunnel.
        /// </summary>
        public readonly string? IpsecConnectionId;
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table used by the DRG attachment.
        /// </summary>
        public readonly string? RouteTableId;
        /// <summary>
        /// (Updatable) The type can be one of these values: `IPSEC_TUNNEL`, `REMOTE_PEERING_CONNECTION`, `VCN`, `VIRTUAL_CIRCUIT`
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// (Updatable) Indicates whether the VCN CIDR(s) or the individual Subnet CIDR(s) are imported from the attachment.  Routes from the VCN Ingress Route Table are always imported. It can be one of these values: `VCN_CIDRS` , `SUBNET_CIDRS`
        /// </summary>
        public readonly string? VcnRouteType;

        [OutputConstructor]
        private DrgAttachmentNetworkDetails(
            string id,

            string? ipsecConnectionId,

            string? routeTableId,

            string type,

            string? vcnRouteType)
        {
            Id = id;
            IpsecConnectionId = ipsecConnectionId;
            RouteTableId = routeTableId;
            Type = type;
            VcnRouteType = vcnRouteType;
        }
    }
}
