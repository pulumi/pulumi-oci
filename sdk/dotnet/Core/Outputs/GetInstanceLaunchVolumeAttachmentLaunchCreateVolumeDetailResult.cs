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
    public sealed class GetInstanceLaunchVolumeAttachmentLaunchCreateVolumeDetailResult
    {
        /// <summary>
        /// The OCID of the compartment containing images to search
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The OCID of the Vault service key to assign as the master encryption key for the boot volume.
        /// </summary>
        public readonly string KmsKeyId;
        public readonly string SizeInGbs;
        public readonly string VolumeCreationType;
        public readonly string VpusPerGb;

        [OutputConstructor]
        private GetInstanceLaunchVolumeAttachmentLaunchCreateVolumeDetailResult(
            string compartmentId,

            string displayName,

            string kmsKeyId,

            string sizeInGbs,

            string volumeCreationType,

            string vpusPerGb)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            KmsKeyId = kmsKeyId;
            SizeInGbs = sizeInGbs;
            VolumeCreationType = volumeCreationType;
            VpusPerGb = vpusPerGb;
        }
    }
}
