// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService.Outputs
{

    [OutputType]
    public sealed class GetBdsInstanceMasterNodeShapeConfigResult
    {
        /// <summary>
        /// The total amount of memory available to the node, in gigabytes.
        /// </summary>
        public readonly int MemoryInGbs;
        /// <summary>
        /// The number of NVMe drives to be used for storage. A single drive has 6.8 TB available.
        /// </summary>
        public readonly int Nvmes;
        /// <summary>
        /// The total number of OCPUs available to the node.
        /// </summary>
        public readonly int Ocpus;

        [OutputConstructor]
        private GetBdsInstanceMasterNodeShapeConfigResult(
            int memoryInGbs,

            int nvmes,

            int ocpus)
        {
            MemoryInGbs = memoryInGbs;
            Nvmes = nvmes;
            Ocpus = ocpus;
        }
    }
}
