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
    public sealed class GetBootVolumeAttachmentsBootVolumeAttachmentResult
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The OCID of the boot volume.
        /// </summary>
        public readonly string BootVolumeId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Refer the top-level definition of encryptionInTransitType. The default value is NONE.
        /// </summary>
        public readonly string EncryptionInTransitType;
        /// <summary>
        /// The OCID of the boot volume attachment.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The OCID of the instance.
        /// </summary>
        public readonly string InstanceId;
        /// <summary>
        /// Whether in-transit encryption for the boot volume's paravirtualized attachment is enabled or not.
        /// </summary>
        public readonly bool IsPvEncryptionInTransitEnabled;
        /// <summary>
        /// The current state of the boot volume attachment.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the boot volume was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the boot volume attachment was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetBootVolumeAttachmentsBootVolumeAttachmentResult(
            string availabilityDomain,

            string bootVolumeId,

            string compartmentId,

            string displayName,

            string encryptionInTransitType,

            string id,

            string instanceId,

            bool isPvEncryptionInTransitEnabled,

            string state,

            string timeCreated,

            string timeUpdated)
        {
            AvailabilityDomain = availabilityDomain;
            BootVolumeId = bootVolumeId;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            EncryptionInTransitType = encryptionInTransitType;
            Id = id;
            InstanceId = instanceId;
            IsPvEncryptionInTransitEnabled = isPvEncryptionInTransitEnabled;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
