// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetAutonomousVirtualMachinesAutonomousVirtualMachineResult
    {
        /// <summary>
        /// The Autonomous Virtual machine [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string AutonomousVmClusterId;
        /// <summary>
        /// Client IP Address.
        /// </summary>
        public readonly string ClientIpAddress;
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The number of CPU cores enabled on the Autonomous Virtual Machine.
        /// </summary>
        public readonly int CpuCoreCount;
        /// <summary>
        /// The allocated local node storage in GBs on the Autonomous Virtual Machine.
        /// </summary>
        public readonly int DbNodeStorageSizeInGbs;
        /// <summary>
        /// The display name of the dbServer associated with the Autonomous Virtual Machine.
        /// </summary>
        public readonly string DbServerDisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Db server associated with the Autonomous Virtual Machine.
        /// </summary>
        public readonly string DbServerId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Virtual Machine.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The allocated memory in GBs on the Autonomous Virtual Machine.
        /// </summary>
        public readonly int MemorySizeInGbs;
        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The name of the Autonomous Virtual Machine.
        /// </summary>
        public readonly string VmName;

        [OutputConstructor]
        private GetAutonomousVirtualMachinesAutonomousVirtualMachineResult(
            string autonomousVmClusterId,

            string clientIpAddress,

            string compartmentId,

            int cpuCoreCount,

            int dbNodeStorageSizeInGbs,

            string dbServerDisplayName,

            string dbServerId,

            ImmutableDictionary<string, object> definedTags,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            int memorySizeInGbs,

            string state,

            string vmName)
        {
            AutonomousVmClusterId = autonomousVmClusterId;
            ClientIpAddress = clientIpAddress;
            CompartmentId = compartmentId;
            CpuCoreCount = cpuCoreCount;
            DbNodeStorageSizeInGbs = dbNodeStorageSizeInGbs;
            DbServerDisplayName = dbServerDisplayName;
            DbServerId = dbServerId;
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            Id = id;
            MemorySizeInGbs = memorySizeInGbs;
            State = state;
            VmName = vmName;
        }
    }
}