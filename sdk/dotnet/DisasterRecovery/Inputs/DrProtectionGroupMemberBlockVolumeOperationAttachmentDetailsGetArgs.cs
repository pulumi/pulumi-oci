// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DisasterRecovery.Inputs
{

    public sealed class DrProtectionGroupMemberBlockVolumeOperationAttachmentDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the reference compute instance from which to obtain the attachment details for the volume. This reference compute instance is from the peer DR protection group.  Example: `ocid1.instance.oc1..uniqueID`
        /// </summary>
        [Input("volumeAttachmentReferenceInstanceId")]
        public Input<string>? VolumeAttachmentReferenceInstanceId { get; set; }

        public DrProtectionGroupMemberBlockVolumeOperationAttachmentDetailsGetArgs()
        {
        }
        public static new DrProtectionGroupMemberBlockVolumeOperationAttachmentDetailsGetArgs Empty => new DrProtectionGroupMemberBlockVolumeOperationAttachmentDetailsGetArgs();
    }
}