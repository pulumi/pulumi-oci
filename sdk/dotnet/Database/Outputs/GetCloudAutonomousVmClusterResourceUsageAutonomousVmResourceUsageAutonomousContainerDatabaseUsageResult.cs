// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetCloudAutonomousVmClusterResourceUsageAutonomousVmResourceUsageAutonomousContainerDatabaseUsageResult
    {
        /// <summary>
        /// The number of CPU cores available.
        /// </summary>
        public readonly double AvailableCpus;
        /// <summary>
        /// The user-friendly name for the Autonomous VM cluster. The name does not need to be unique.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Cloud Autonomous VM cluster.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The number of CPUs provisioned in an Autonomous VM Cluster.
        /// </summary>
        public readonly double ProvisionedCpus;
        /// <summary>
        /// CPU cores that continue to be included in the count of OCPUs available to the Autonomous Container Database even after one of its Autonomous Database is terminated or scaled down. You can release them to the available OCPUs at its parent AVMC level by restarting the Autonomous Container Database.
        /// </summary>
        public readonly double ReclaimableCpus;
        /// <summary>
        /// The number of CPUs reserved in an Autonomous VM Cluster.
        /// </summary>
        public readonly double ReservedCpus;
        /// <summary>
        /// The number of CPU cores alloted to the Autonomous Container Databases in an Cloud Autonomous VM cluster.
        /// </summary>
        public readonly double UsedCpus;

        [OutputConstructor]
        private GetCloudAutonomousVmClusterResourceUsageAutonomousVmResourceUsageAutonomousContainerDatabaseUsageResult(
            double availableCpus,

            string displayName,

            string id,

            double provisionedCpus,

            double reclaimableCpus,

            double reservedCpus,

            double usedCpus)
        {
            AvailableCpus = availableCpus;
            DisplayName = displayName;
            Id = id;
            ProvisionedCpus = provisionedCpus;
            ReclaimableCpus = reclaimableCpus;
            ReservedCpus = reservedCpus;
            UsedCpus = usedCpus;
        }
    }
}
