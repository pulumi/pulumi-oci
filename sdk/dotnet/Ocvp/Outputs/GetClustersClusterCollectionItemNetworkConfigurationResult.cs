// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Ocvp.Outputs
{

    [OutputType]
    public sealed class GetClustersClusterCollectionItemNetworkConfigurationResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the HCX component of the VMware environment. This VLAN is a mandatory attribute  for Management Cluster when HCX is enabled.
        /// </summary>
        public readonly string HcxVlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the NSX Edge Uplink 1 component of the VMware environment. This VLAN is a mandatory attribute for Management Cluster.
        /// </summary>
        public readonly string NsxEdgeUplink1vlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC  for the NSX Edge Uplink 2 component of the VMware environment. This VLAN is a mandatory attribute for Management Cluster.
        /// </summary>
        public readonly string NsxEdgeUplink2vlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the NSX Edge VTEP component of the VMware environment.
        /// </summary>
        public readonly string NsxEdgeVtepVlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the NSX VTEP component of the VMware environment.
        /// </summary>
        public readonly string NsxVtepVlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management subnet used to provision the Cluster.
        /// </summary>
        public readonly string ProvisioningSubnetId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the Provisioning component of the VMware environment.
        /// </summary>
        public readonly string ProvisioningVlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the vSphere Replication component of the VMware environment.
        /// </summary>
        public readonly string ReplicationVlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the vMotion component of the VMware environment.
        /// </summary>
        public readonly string VmotionVlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the Cluster for the vSAN component of the VMware environment.
        /// </summary>
        public readonly string VsanVlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN used by the SDDC for the vSphere component of the VMware environment. This VLAN is a mandatory attribute for Management Cluster.
        /// </summary>
        public readonly string VsphereVlanId;

        [OutputConstructor]
        private GetClustersClusterCollectionItemNetworkConfigurationResult(
            string hcxVlanId,

            string nsxEdgeUplink1vlanId,

            string nsxEdgeUplink2vlanId,

            string nsxEdgeVtepVlanId,

            string nsxVtepVlanId,

            string provisioningSubnetId,

            string provisioningVlanId,

            string replicationVlanId,

            string vmotionVlanId,

            string vsanVlanId,

            string vsphereVlanId)
        {
            HcxVlanId = hcxVlanId;
            NsxEdgeUplink1vlanId = nsxEdgeUplink1vlanId;
            NsxEdgeUplink2vlanId = nsxEdgeUplink2vlanId;
            NsxEdgeVtepVlanId = nsxEdgeVtepVlanId;
            NsxVtepVlanId = nsxVtepVlanId;
            ProvisioningSubnetId = provisioningSubnetId;
            ProvisioningVlanId = provisioningVlanId;
            ReplicationVlanId = replicationVlanId;
            VmotionVlanId = vmotionVlanId;
            VsanVlanId = vsanVlanId;
            VsphereVlanId = vsphereVlanId;
        }
    }
}
