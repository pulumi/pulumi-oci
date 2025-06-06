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
    public sealed class InstanceConfigurationInstanceDetailsOption
    {
        /// <summary>
        /// Block volume parameters.
        /// </summary>
        public readonly ImmutableArray<Outputs.InstanceConfigurationInstanceDetailsOptionBlockVolume> BlockVolumes;
        /// <summary>
        /// Instance launch details for creating an instance from an instance configuration. Use the `sourceDetails` parameter to specify whether a boot volume or an image should be used to launch a new instance.
        /// 
        /// See [LaunchInstanceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/LaunchInstanceDetails) for more information.
        /// </summary>
        public readonly Outputs.InstanceConfigurationInstanceDetailsOptionLaunchDetails? LaunchDetails;
        /// <summary>
        /// Secondary VNIC parameters.
        /// </summary>
        public readonly ImmutableArray<Outputs.InstanceConfigurationInstanceDetailsOptionSecondaryVnic> SecondaryVnics;

        [OutputConstructor]
        private InstanceConfigurationInstanceDetailsOption(
            ImmutableArray<Outputs.InstanceConfigurationInstanceDetailsOptionBlockVolume> blockVolumes,

            Outputs.InstanceConfigurationInstanceDetailsOptionLaunchDetails? launchDetails,

            ImmutableArray<Outputs.InstanceConfigurationInstanceDetailsOptionSecondaryVnic> secondaryVnics)
        {
            BlockVolumes = blockVolumes;
            LaunchDetails = launchDetails;
            SecondaryVnics = secondaryVnics;
        }
    }
}
