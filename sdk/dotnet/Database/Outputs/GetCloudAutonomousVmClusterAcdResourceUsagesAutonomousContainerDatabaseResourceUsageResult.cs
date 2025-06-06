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
    public sealed class GetCloudAutonomousVmClusterAcdResourceUsagesAutonomousContainerDatabaseResourceUsageResult
    {
        /// <summary>
        /// List of autonomous container database resource usage per autonomous virtual machine.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCloudAutonomousVmClusterAcdResourceUsagesAutonomousContainerDatabaseResourceUsageAutonomousContainerDatabaseVmUsageResult> AutonomousContainerDatabaseVmUsages;
        /// <summary>
        /// CPUs available for provisioning or scaling an Autonomous Database in the Autonomous Container Database.
        /// </summary>
        public readonly double AvailableCpus;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The user-friendly name for the Autonomous Container Database. The name does not need to be unique.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Container Database.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Largest provisionable ADB in the Autonomous Container Database.
        /// </summary>
        public readonly double LargestProvisionableAutonomousDatabaseInCpus;
        /// <summary>
        /// Valid list of provisionable CPUs for Autonomous Database.
        /// </summary>
        public readonly ImmutableArray<double> ProvisionableCpuses;
        /// <summary>
        /// CPUs / cores assigned to ADBs in the Autonomous Container Database.
        /// </summary>
        public readonly double ProvisionedCpus;
        /// <summary>
        /// Number of CPUs that are reclaimable or released to the AVMC on Autonomous Container Database restart.
        /// </summary>
        public readonly double ReclaimableCpus;
        /// <summary>
        /// CPUs / cores reserved for scalability, resilliency and other overheads. This includes failover, autoscaling and idle instance overhead.
        /// </summary>
        public readonly double ReservedCpus;
        /// <summary>
        /// CPUs / cores assigned to the Autonomous Container Database. Sum of provisioned, reserved and reclaimable CPUs/ cores.
        /// </summary>
        public readonly double UsedCpus;

        [OutputConstructor]
        private GetCloudAutonomousVmClusterAcdResourceUsagesAutonomousContainerDatabaseResourceUsageResult(
            ImmutableArray<Outputs.GetCloudAutonomousVmClusterAcdResourceUsagesAutonomousContainerDatabaseResourceUsageAutonomousContainerDatabaseVmUsageResult> autonomousContainerDatabaseVmUsages,

            double availableCpus,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            double largestProvisionableAutonomousDatabaseInCpus,

            ImmutableArray<double> provisionableCpuses,

            double provisionedCpus,

            double reclaimableCpus,

            double reservedCpus,

            double usedCpus)
        {
            AutonomousContainerDatabaseVmUsages = autonomousContainerDatabaseVmUsages;
            AvailableCpus = availableCpus;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LargestProvisionableAutonomousDatabaseInCpus = largestProvisionableAutonomousDatabaseInCpus;
            ProvisionableCpuses = provisionableCpuses;
            ProvisionedCpus = provisionedCpus;
            ReclaimableCpus = reclaimableCpus;
            ReservedCpus = reservedCpus;
            UsedCpus = usedCpus;
        }
    }
}
