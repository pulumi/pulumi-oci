// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetExternalAsmConfigurationInitParameterResult
    {
        /// <summary>
        /// The user-friendly name for the ASM instance. The name does not have to be unique.
        /// </summary>
        public readonly string AsmInstanceDisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM instance.
        /// </summary>
        public readonly string AsmInstanceId;
        /// <summary>
        /// The list of disk group names that an ASM instance mounts at startup or when the `ALTER DISKGROUP ALL MOUNT` statement is issued.
        /// </summary>
        public readonly ImmutableArray<string> AutoMountDiskGroups;
        /// <summary>
        /// An operating system-dependent value used to limit the set of disks considered for discovery.
        /// </summary>
        public readonly string DiskDiscoveryPath;
        /// <summary>
        /// The list of failure groups that contain preferred read disks.
        /// </summary>
        public readonly ImmutableArray<string> PreferredReadFailureGroups;
        /// <summary>
        /// The maximum power on an ASM instance for disk rebalancing.
        /// </summary>
        public readonly int RebalancePower;

        [OutputConstructor]
        private GetExternalAsmConfigurationInitParameterResult(
            string asmInstanceDisplayName,

            string asmInstanceId,

            ImmutableArray<string> autoMountDiskGroups,

            string diskDiscoveryPath,

            ImmutableArray<string> preferredReadFailureGroups,

            int rebalancePower)
        {
            AsmInstanceDisplayName = asmInstanceDisplayName;
            AsmInstanceId = asmInstanceId;
            AutoMountDiskGroups = autoMountDiskGroups;
            DiskDiscoveryPath = diskDiscoveryPath;
            PreferredReadFailureGroups = preferredReadFailureGroups;
            RebalancePower = rebalancePower;
        }
    }
}