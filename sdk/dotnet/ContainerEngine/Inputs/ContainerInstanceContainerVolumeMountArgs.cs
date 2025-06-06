// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Inputs
{

    public sealed class ContainerInstanceContainerVolumeMountArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Whether the volume was mounted in read-only mode. By default, the volume is not read-only.
        /// </summary>
        [Input("isReadOnly")]
        public Input<bool>? IsReadOnly { get; set; }

        /// <summary>
        /// The volume access path.
        /// </summary>
        [Input("mountPath", required: true)]
        public Input<string> MountPath { get; set; } = null!;

        /// <summary>
        /// If there is more than one partition in the volume, reference this number of partitions. Here is an example: Number  Start   End     Size    File system  Name                  Flags 1      1049kB  106MB   105MB   fat16        EFI System Partition  boot, esp 2      106MB   1180MB  1074MB  xfs 3      1180MB  50.0GB  48.8GB                                     lvm
        /// </summary>
        [Input("partition")]
        public Input<int>? Partition { get; set; }

        /// <summary>
        /// A subpath inside the referenced volume.
        /// </summary>
        [Input("subPath")]
        public Input<string>? SubPath { get; set; }

        /// <summary>
        /// The name of the volume. Avoid entering confidential information.
        /// </summary>
        [Input("volumeName", required: true)]
        public Input<string> VolumeName { get; set; } = null!;

        public ContainerInstanceContainerVolumeMountArgs()
        {
        }
        public static new ContainerInstanceContainerVolumeMountArgs Empty => new ContainerInstanceContainerVolumeMountArgs();
    }
}
