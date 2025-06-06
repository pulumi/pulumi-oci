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
    public sealed class ContainerInstanceContainerResourceConfig
    {
        /// <summary>
        /// The maximum amount of memory that can be consumed by the container's process.
        /// 
        /// If you do not set a value, then the process may use all available memory on the instance.
        /// </summary>
        public readonly double? MemoryLimitInGbs;
        /// <summary>
        /// The maximum amount of CPUs that can be consumed by the container's process.
        /// 
        /// If you do not set a value, then the process can use all available CPU resources on the instance.
        /// 
        /// CPU usage is defined in terms of logical CPUs. This means that the maximum possible value on an E3 ContainerInstance with 1 OCPU is 2.0.
        /// 
        /// A container with a 2.0 vcpusLimit could consume up to 100% of the CPU resources available on the container instance. Values can be fractional. A value of "1.5" means that the container can consume at most the equivalent of 1 and a half logical CPUs worth of CPU capacity.
        /// </summary>
        public readonly double? VcpusLimit;

        [OutputConstructor]
        private ContainerInstanceContainerResourceConfig(
            double? memoryLimitInGbs,

            double? vcpusLimit)
        {
            MemoryLimitInGbs = memoryLimitInGbs;
            VcpusLimit = vcpusLimit;
        }
    }
}
