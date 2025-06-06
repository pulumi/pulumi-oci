// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class ContainerInstanceVolume
    {
        /// <summary>
        /// The volume type of the empty directory, can be either File Storage or Memory.
        /// </summary>
        public readonly string? BackingStore;
        /// <summary>
        /// Contains key value pairs which can be mounted as individual files inside the container. The value needs to be base64 encoded. It is decoded to plain text before the mount.
        /// </summary>
        public readonly ImmutableArray<Outputs.ContainerInstanceVolumeConfig> Configs;
        /// <summary>
        /// The name of the volume. This must be unique within a single container instance.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The type of volume.
        /// </summary>
        public readonly string VolumeType;

        [OutputConstructor]
        private ContainerInstanceVolume(
            string? backingStore,

            ImmutableArray<Outputs.ContainerInstanceVolumeConfig> configs,

            string name,

            string volumeType)
        {
            BackingStore = backingStore;
            Configs = configs;
            Name = name;
            VolumeType = volumeType;
        }
    }
}
