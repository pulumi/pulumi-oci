// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataFlow.Outputs
{

    [OutputType]
    public sealed class PoolConfigurationShapeConfig
    {
        /// <summary>
        /// (Updatable) The amount of memory used for the driver or executors.
        /// </summary>
        public readonly double? MemoryInGbs;
        /// <summary>
        /// (Updatable) The total number of OCPUs used for the driver or executors. See [here](https://docs.cloud.oracle.com/en-us/iaas/api/#/en/iaas/20160918/Shape/) for details.
        /// </summary>
        public readonly double? Ocpus;

        [OutputConstructor]
        private PoolConfigurationShapeConfig(
            double? memoryInGbs,

            double? ocpus)
        {
            MemoryInGbs = memoryInGbs;
            Ocpus = ocpus;
        }
    }
}