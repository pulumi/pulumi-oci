// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DisasterRecovery.Inputs
{

    public sealed class DrProtectionGroupMemberExportMappingGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the destination mount target in the destination region which is used to export the file system.  Example: `ocid1.mounttarget.oc1..uniqueID`
        /// </summary>
        [Input("destinationMountTargetId")]
        public Input<string>? DestinationMountTargetId { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the export path in the primary region used to mount or unmount the file system.  Example: `ocid1.export.oc1..uniqueID`
        /// </summary>
        [Input("exportId")]
        public Input<string>? ExportId { get; set; }

        public DrProtectionGroupMemberExportMappingGetArgs()
        {
        }
        public static new DrProtectionGroupMemberExportMappingGetArgs Empty => new DrProtectionGroupMemberExportMappingGetArgs();
    }
}
