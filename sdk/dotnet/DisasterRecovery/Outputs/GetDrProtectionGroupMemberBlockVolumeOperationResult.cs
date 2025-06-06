// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DisasterRecovery.Outputs
{

    [OutputType]
    public sealed class GetDrProtectionGroupMemberBlockVolumeOperationResult
    {
        /// <summary>
        /// Deprecated. Use the 'ComputeInstanceNonMovableBlockVolumeAttachOperationDetails' definition instead of this. The details for attaching or detaching a block volume.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDrProtectionGroupMemberBlockVolumeOperationAttachmentDetailResult> AttachmentDetails;
        /// <summary>
        /// The OCID of the block volume.  Example: `ocid1.volume.oc1..uniqueID`
        /// </summary>
        public readonly string BlockVolumeId;
        /// <summary>
        /// Mount details of a file system.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDrProtectionGroupMemberBlockVolumeOperationMountDetailResult> MountDetails;

        [OutputConstructor]
        private GetDrProtectionGroupMemberBlockVolumeOperationResult(
            ImmutableArray<Outputs.GetDrProtectionGroupMemberBlockVolumeOperationAttachmentDetailResult> attachmentDetails,

            string blockVolumeId,

            ImmutableArray<Outputs.GetDrProtectionGroupMemberBlockVolumeOperationMountDetailResult> mountDetails)
        {
            AttachmentDetails = attachmentDetails;
            BlockVolumeId = blockVolumeId;
            MountDetails = mountDetails;
        }
    }
}
