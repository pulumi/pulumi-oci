// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DisasterRecovery.Inputs
{

    public sealed class DrProtectionGroupMemberFileSystemOperationUnmountDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the mount target.  Example: `ocid1.mounttarget.oc1..uniqueID`
        /// </summary>
        [Input("mountTargetId")]
        public Input<string>? MountTargetId { get; set; }

        public DrProtectionGroupMemberFileSystemOperationUnmountDetailsGetArgs()
        {
        }
        public static new DrProtectionGroupMemberFileSystemOperationUnmountDetailsGetArgs Empty => new DrProtectionGroupMemberFileSystemOperationUnmountDetailsGetArgs();
    }
}
