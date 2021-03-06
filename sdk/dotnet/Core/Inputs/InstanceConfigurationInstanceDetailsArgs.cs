// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class InstanceConfigurationInstanceDetailsArgs : Pulumi.ResourceArgs
    {
        [Input("blockVolumes")]
        private InputList<Inputs.InstanceConfigurationInstanceDetailsBlockVolumeArgs>? _blockVolumes;
        public InputList<Inputs.InstanceConfigurationInstanceDetailsBlockVolumeArgs> BlockVolumes
        {
            get => _blockVolumes ?? (_blockVolumes = new InputList<Inputs.InstanceConfigurationInstanceDetailsBlockVolumeArgs>());
            set => _blockVolumes = value;
        }

        /// <summary>
        /// The type of instance details. Supported instanceType is compute
        /// </summary>
        [Input("instanceType", required: true)]
        public Input<string> InstanceType { get; set; } = null!;

        /// <summary>
        /// Instance launch details for creating an instance from an instance configuration. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
        /// </summary>
        [Input("launchDetails")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsArgs>? LaunchDetails { get; set; }

        [Input("secondaryVnics")]
        private InputList<Inputs.InstanceConfigurationInstanceDetailsSecondaryVnicArgs>? _secondaryVnics;
        public InputList<Inputs.InstanceConfigurationInstanceDetailsSecondaryVnicArgs> SecondaryVnics
        {
            get => _secondaryVnics ?? (_secondaryVnics = new InputList<Inputs.InstanceConfigurationInstanceDetailsSecondaryVnicArgs>());
            set => _secondaryVnics = value;
        }

        public InstanceConfigurationInstanceDetailsArgs()
        {
        }
    }
}
