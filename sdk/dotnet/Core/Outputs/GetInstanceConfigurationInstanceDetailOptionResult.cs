// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetInstanceConfigurationInstanceDetailOptionResult
    {
        /// <summary>
        /// Block volume parameters.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInstanceConfigurationInstanceDetailOptionBlockVolumeResult> BlockVolumes;
        /// <summary>
        /// Instance launch details for creating an instance from an instance configuration. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInstanceConfigurationInstanceDetailOptionLaunchDetailResult> LaunchDetails;
        /// <summary>
        /// Secondary VNIC parameters.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInstanceConfigurationInstanceDetailOptionSecondaryVnicResult> SecondaryVnics;

        [OutputConstructor]
        private GetInstanceConfigurationInstanceDetailOptionResult(
            ImmutableArray<Outputs.GetInstanceConfigurationInstanceDetailOptionBlockVolumeResult> blockVolumes,

            ImmutableArray<Outputs.GetInstanceConfigurationInstanceDetailOptionLaunchDetailResult> launchDetails,

            ImmutableArray<Outputs.GetInstanceConfigurationInstanceDetailOptionSecondaryVnicResult> secondaryVnics)
        {
            BlockVolumes = blockVolumes;
            LaunchDetails = launchDetails;
            SecondaryVnics = secondaryVnics;
        }
    }
}