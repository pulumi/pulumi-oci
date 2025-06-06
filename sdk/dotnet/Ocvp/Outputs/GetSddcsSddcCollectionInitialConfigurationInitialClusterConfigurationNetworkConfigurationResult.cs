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
    public sealed class GetSddcsSddcCollectionInitialConfigurationInitialClusterConfigurationNetworkConfigurationResult
    {
        public readonly string HcxVlanId;
        public readonly string NsxEdgeUplink1vlanId;
        public readonly string NsxEdgeUplink2vlanId;
        public readonly string NsxEdgeVtepVlanId;
        public readonly string NsxVtepVlanId;
        public readonly string ProvisioningSubnetId;
        public readonly string ProvisioningVlanId;
        public readonly string ReplicationVlanId;
        public readonly string VmotionVlanId;
        public readonly string VsanVlanId;
        public readonly string VsphereVlanId;

        [OutputConstructor]
        private GetSddcsSddcCollectionInitialConfigurationInitialClusterConfigurationNetworkConfigurationResult(
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
