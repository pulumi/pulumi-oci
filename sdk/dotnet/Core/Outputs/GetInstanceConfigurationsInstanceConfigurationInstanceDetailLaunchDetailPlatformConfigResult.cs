// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetInstanceConfigurationsInstanceConfigurationInstanceDetailLaunchDetailPlatformConfigResult
    {
        /// <summary>
        /// Whether virtualization instructions are available.
        /// </summary>
        public readonly bool AreVirtualInstructionsEnabled;
        /// <summary>
        /// Whether the Access Control Service is enabled on the instance. When enabled, the platform can enforce PCIe device isolation, required for VFIO device passthrough.
        /// </summary>
        public readonly bool IsAccessControlServiceEnabled;
        /// <summary>
        /// Whether the input-output memory management unit is enabled.
        /// </summary>
        public readonly bool IsInputOutputMemoryManagementUnitEnabled;
        /// <summary>
        /// Whether the Measured Boot feature is enabled on the instance.
        /// </summary>
        public readonly bool IsMeasuredBootEnabled;
        /// <summary>
        /// Whether Secure Boot is enabled on the instance.
        /// </summary>
        public readonly bool IsSecureBootEnabled;
        /// <summary>
        /// Whether symmetric multi-threading is enabled on the instance.
        /// </summary>
        public readonly bool IsSymmetricMultiThreadingEnabled;
        /// <summary>
        /// Whether the Trusted Platform Module (TPM) is enabled on the instance.
        /// </summary>
        public readonly bool IsTrustedPlatformModuleEnabled;
        /// <summary>
        /// The number of NUMA nodes per socket (NPS).
        /// </summary>
        public readonly string NumaNodesPerSocket;
        /// <summary>
        /// The percentage of cores enabled.
        /// </summary>
        public readonly int PercentageOfCoresEnabled;
        /// <summary>
        /// The type of action to run when the instance is interrupted for eviction.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetInstanceConfigurationsInstanceConfigurationInstanceDetailLaunchDetailPlatformConfigResult(
            bool areVirtualInstructionsEnabled,

            bool isAccessControlServiceEnabled,

            bool isInputOutputMemoryManagementUnitEnabled,

            bool isMeasuredBootEnabled,

            bool isSecureBootEnabled,

            bool isSymmetricMultiThreadingEnabled,

            bool isTrustedPlatformModuleEnabled,

            string numaNodesPerSocket,

            int percentageOfCoresEnabled,

            string type)
        {
            AreVirtualInstructionsEnabled = areVirtualInstructionsEnabled;
            IsAccessControlServiceEnabled = isAccessControlServiceEnabled;
            IsInputOutputMemoryManagementUnitEnabled = isInputOutputMemoryManagementUnitEnabled;
            IsMeasuredBootEnabled = isMeasuredBootEnabled;
            IsSecureBootEnabled = isSecureBootEnabled;
            IsSymmetricMultiThreadingEnabled = isSymmetricMultiThreadingEnabled;
            IsTrustedPlatformModuleEnabled = isTrustedPlatformModuleEnabled;
            NumaNodesPerSocket = numaNodesPerSocket;
            PercentageOfCoresEnabled = percentageOfCoresEnabled;
            Type = type;
        }
    }
}