// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Ocvp.Outputs
{

    [OutputType]
    public sealed class SddcInitialConfiguration
    {
        /// <summary>
        /// The configurations for Clusters initially created in the SDDC.
        /// </summary>
        public readonly ImmutableArray<Outputs.SddcInitialConfigurationInitialClusterConfiguration> InitialClusterConfigurations;

        [OutputConstructor]
        private SddcInitialConfiguration(ImmutableArray<Outputs.SddcInitialConfigurationInitialClusterConfiguration> initialClusterConfigurations)
        {
            InitialClusterConfigurations = initialClusterConfigurations;
        }
    }
}
