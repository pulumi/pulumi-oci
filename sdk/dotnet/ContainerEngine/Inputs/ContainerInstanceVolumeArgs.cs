// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Inputs
{

    public sealed class ContainerInstanceVolumeArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Volume type that we are using for empty dir where it could be either File Storage or Memory
        /// </summary>
        [Input("backingStore")]
        public Input<string>? BackingStore { get; set; }

        [Input("configs")]
        private InputList<Inputs.ContainerInstanceVolumeConfigArgs>? _configs;

        /// <summary>
        /// Contains key value pairs which can be mounted as individual files inside the container. The value needs to be base64 encoded. It is decoded to plain text before the mount.
        /// </summary>
        public InputList<Inputs.ContainerInstanceVolumeConfigArgs> Configs
        {
            get => _configs ?? (_configs = new InputList<Inputs.ContainerInstanceVolumeConfigArgs>());
            set => _configs = value;
        }

        /// <summary>
        /// The name of the volume. This has be unique cross single ContainerInstance.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        /// <summary>
        /// The type of volume.
        /// </summary>
        [Input("volumeType", required: true)]
        public Input<string> VolumeType { get; set; } = null!;

        public ContainerInstanceVolumeArgs()
        {
        }
        public static new ContainerInstanceVolumeArgs Empty => new ContainerInstanceVolumeArgs();
    }
}