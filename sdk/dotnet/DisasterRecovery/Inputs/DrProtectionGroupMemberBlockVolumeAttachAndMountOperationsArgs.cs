// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DisasterRecovery.Inputs
{

    public sealed class DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsArgs : global::Pulumi.ResourceArgs
    {
        [Input("attachments")]
        private InputList<Inputs.DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsAttachmentArgs>? _attachments;

        /// <summary>
        /// (Updatable) A list of details of attach or detach operations performed on block volumes.
        /// </summary>
        public InputList<Inputs.DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsAttachmentArgs> Attachments
        {
            get => _attachments ?? (_attachments = new InputList<Inputs.DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsAttachmentArgs>());
            set => _attachments = value;
        }

        [Input("mounts")]
        private InputList<Inputs.DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsMountArgs>? _mounts;

        /// <summary>
        /// (Updatable) A list of details of mount operations performed on block volumes.
        /// </summary>
        public InputList<Inputs.DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsMountArgs> Mounts
        {
            get => _mounts ?? (_mounts = new InputList<Inputs.DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsMountArgs>());
            set => _mounts = value;
        }

        public DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsArgs()
        {
        }
        public static new DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsArgs Empty => new DrProtectionGroupMemberBlockVolumeAttachAndMountOperationsArgs();
    }
}
