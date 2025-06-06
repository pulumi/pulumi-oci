// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetVnicAttachmentsVnicAttachmentResult
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetVnicAttachmentsVnicAttachmentCreateVnicDetailResult> CreateVnicDetails;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The OCID of the VNIC attachment.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The OCID of the instance.
        /// </summary>
        public readonly string InstanceId;
        /// <summary>
        /// Which physical network interface card (NIC) the VNIC uses. Certain bare metal instance shapes have two active physical NICs (0 and 1). If you add a secondary VNIC to one of these instances, you can specify which NIC the VNIC will use. For more information, see [Virtual Network Interface Cards (VNICs)](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVNICs.htm).
        /// </summary>
        public readonly int NicIndex;
        /// <summary>
        /// The current state of the VNIC attachment.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The OCID of the subnet to create the VNIC in.
        /// </summary>
        public readonly string SubnetId;
        /// <summary>
        /// The date and time the VNIC attachment was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The OCID of the VLAN to create the VNIC in. Creating the VNIC in a VLAN (instead of a subnet) is possible only if you are an Oracle Cloud VMware Solution customer. See [Vlan](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Vlan).
        /// </summary>
        public readonly string VlanId;
        /// <summary>
        /// The Oracle-assigned VLAN tag of the attached VNIC. Available after the attachment process is complete.
        /// </summary>
        public readonly int VlanTag;
        /// <summary>
        /// The OCID of the VNIC.
        /// </summary>
        public readonly string VnicId;

        [OutputConstructor]
        private GetVnicAttachmentsVnicAttachmentResult(
            string availabilityDomain,

            string compartmentId,

            ImmutableArray<Outputs.GetVnicAttachmentsVnicAttachmentCreateVnicDetailResult> createVnicDetails,

            string displayName,

            string id,

            string instanceId,

            int nicIndex,

            string state,

            string subnetId,

            string timeCreated,

            string vlanId,

            int vlanTag,

            string vnicId)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            CreateVnicDetails = createVnicDetails;
            DisplayName = displayName;
            Id = id;
            InstanceId = instanceId;
            NicIndex = nicIndex;
            State = state;
            SubnetId = subnetId;
            TimeCreated = timeCreated;
            VlanId = vlanId;
            VlanTag = vlanTag;
            VnicId = vnicId;
        }
    }
}
