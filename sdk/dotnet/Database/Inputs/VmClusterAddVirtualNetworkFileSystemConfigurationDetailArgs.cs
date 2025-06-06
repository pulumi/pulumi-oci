// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class VmClusterAddVirtualNetworkFileSystemConfigurationDetailArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The file system size to be allocated in GBs.
        /// </summary>
        [Input("fileSystemSizeGb")]
        public Input<int>? FileSystemSizeGb { get; set; }

        /// <summary>
        /// The mount point of file system.
        /// </summary>
        [Input("mountPoint")]
        public Input<string>? MountPoint { get; set; }

        public VmClusterAddVirtualNetworkFileSystemConfigurationDetailArgs()
        {
        }
        public static new VmClusterAddVirtualNetworkFileSystemConfigurationDetailArgs Empty => new VmClusterAddVirtualNetworkFileSystemConfigurationDetailArgs();
    }
}
