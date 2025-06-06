// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudMigrations.Outputs
{

    [OutputType]
    public sealed class GetMigrationPlanAvailableShapeItemResult
    {
        /// <summary>
        /// The availability domain in which to list resources.
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. It exists only for cross-compatibility. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Description of the GPUs.
        /// </summary>
        public readonly string GpuDescription;
        /// <summary>
        /// Number of GPUs.
        /// </summary>
        public readonly int Gpus;
        /// <summary>
        /// Description of local disks.
        /// </summary>
        public readonly string LocalDiskDescription;
        /// <summary>
        /// Number of local disks.
        /// </summary>
        public readonly int LocalDisks;
        /// <summary>
        /// Total size of local disks for shape.
        /// </summary>
        public readonly double LocalDisksTotalSizeInGbs;
        /// <summary>
        /// Maximum number of virtual network interfaces that can be attached.
        /// </summary>
        public readonly int MaxVnicAttachments;
        /// <summary>
        /// Amount of memory for the shape.
        /// </summary>
        public readonly double MemoryInGbs;
        /// <summary>
        /// Minimum CPUs required.
        /// </summary>
        public readonly double MinTotalBaselineOcpusRequired;
        /// <summary>
        /// Shape bandwidth.
        /// </summary>
        public readonly double NetworkingBandwidthInGbps;
        /// <summary>
        /// Number of CPUs.
        /// </summary>
        public readonly double Ocpus;
        /// <summary>
        /// Shape name and availability domain.  Used for pagination.
        /// </summary>
        public readonly string PaginationToken;
        /// <summary>
        /// Description of the processor.
        /// </summary>
        public readonly string ProcessorDescription;
        /// <summary>
        /// Name of the shape.
        /// </summary>
        public readonly string Shape;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;

        [OutputConstructor]
        private GetMigrationPlanAvailableShapeItemResult(
            string availabilityDomain,

            ImmutableDictionary<string, string> definedTags,

            ImmutableDictionary<string, string> freeformTags,

            string gpuDescription,

            int gpus,

            string localDiskDescription,

            int localDisks,

            double localDisksTotalSizeInGbs,

            int maxVnicAttachments,

            double memoryInGbs,

            double minTotalBaselineOcpusRequired,

            double networkingBandwidthInGbps,

            double ocpus,

            string paginationToken,

            string processorDescription,

            string shape,

            ImmutableDictionary<string, string> systemTags)
        {
            AvailabilityDomain = availabilityDomain;
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            GpuDescription = gpuDescription;
            Gpus = gpus;
            LocalDiskDescription = localDiskDescription;
            LocalDisks = localDisks;
            LocalDisksTotalSizeInGbs = localDisksTotalSizeInGbs;
            MaxVnicAttachments = maxVnicAttachments;
            MemoryInGbs = memoryInGbs;
            MinTotalBaselineOcpusRequired = minTotalBaselineOcpusRequired;
            NetworkingBandwidthInGbps = networkingBandwidthInGbps;
            Ocpus = ocpus;
            PaginationToken = paginationToken;
            ProcessorDescription = processorDescription;
            Shape = shape;
            SystemTags = systemTags;
        }
    }
}
