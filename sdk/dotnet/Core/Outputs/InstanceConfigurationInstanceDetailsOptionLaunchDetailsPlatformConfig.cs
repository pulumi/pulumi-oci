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
    public sealed class InstanceConfigurationInstanceDetailsOptionLaunchDetailsPlatformConfig
    {
        /// <summary>
        /// Whether virtualization instructions are available. For example, Secure Virtual Machine for AMD shapes or VT-x for Intel shapes.
        /// </summary>
        public readonly bool? AreVirtualInstructionsEnabled;
        /// <summary>
        /// Whether the Access Control Service is enabled on the instance. When enabled, the platform can enforce PCIe device isolation, required for VFIO device pass-through.
        /// </summary>
        public readonly bool? IsAccessControlServiceEnabled;
        /// <summary>
        /// Whether the input-output memory management unit is enabled.
        /// </summary>
        public readonly bool? IsInputOutputMemoryManagementUnitEnabled;
        /// <summary>
        /// Whether the Measured Boot feature is enabled on the instance.
        /// </summary>
        public readonly bool? IsMeasuredBootEnabled;
        /// <summary>
        /// Whether the instance is a confidential instance. If this value is `true`, the instance is a confidential instance. The default value is `false`.
        /// </summary>
        public readonly bool? IsMemoryEncryptionEnabled;
        /// <summary>
        /// Whether Secure Boot is enabled on the instance.
        /// </summary>
        public readonly bool? IsSecureBootEnabled;
        /// <summary>
        /// Whether symmetric multithreading is enabled on the instance. Symmetric multithreading is also called simultaneous multithreading (SMT) or Intel Hyper-Threading.
        /// 
        /// Intel and AMD processors have two hardware execution threads per core (OCPU). SMT permits multiple independent threads of execution, to better use the resources and increase the efficiency of the CPU. When multithreading is disabled, only one thread is permitted to run on each core, which can provide higher or more predictable performance for some workloads.
        /// </summary>
        public readonly bool? IsSymmetricMultiThreadingEnabled;
        /// <summary>
        /// Whether the Trusted Platform Module (TPM) is enabled on the instance.
        /// </summary>
        public readonly bool? IsTrustedPlatformModuleEnabled;
        /// <summary>
        /// The number of NUMA nodes per socket (NPS).
        /// </summary>
        public readonly string? NumaNodesPerSocket;
        /// <summary>
        /// The percentage of cores enabled. Value must be a multiple of 25%. If the requested percentage results in a fractional number of cores, the system rounds up the number of cores across processors and provisions an instance with a whole number of cores.
        /// 
        /// If the applications that you run on the instance use a core-based licensing model and need fewer cores than the full size of the shape, you can disable cores to reduce your licensing costs. The instance itself is billed for the full shape, regardless of whether all cores are enabled.
        /// </summary>
        public readonly int? PercentageOfCoresEnabled;
        /// <summary>
        /// The type of action to run when the instance is interrupted for eviction.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private InstanceConfigurationInstanceDetailsOptionLaunchDetailsPlatformConfig(
            bool? areVirtualInstructionsEnabled,

            bool? isAccessControlServiceEnabled,

            bool? isInputOutputMemoryManagementUnitEnabled,

            bool? isMeasuredBootEnabled,

            bool? isMemoryEncryptionEnabled,

            bool? isSecureBootEnabled,

            bool? isSymmetricMultiThreadingEnabled,

            bool? isTrustedPlatformModuleEnabled,

            string? numaNodesPerSocket,

            int? percentageOfCoresEnabled,

            string type)
        {
            AreVirtualInstructionsEnabled = areVirtualInstructionsEnabled;
            IsAccessControlServiceEnabled = isAccessControlServiceEnabled;
            IsInputOutputMemoryManagementUnitEnabled = isInputOutputMemoryManagementUnitEnabled;
            IsMeasuredBootEnabled = isMeasuredBootEnabled;
            IsMemoryEncryptionEnabled = isMemoryEncryptionEnabled;
            IsSecureBootEnabled = isSecureBootEnabled;
            IsSymmetricMultiThreadingEnabled = isSymmetricMultiThreadingEnabled;
            IsTrustedPlatformModuleEnabled = isTrustedPlatformModuleEnabled;
            NumaNodesPerSocket = numaNodesPerSocket;
            PercentageOfCoresEnabled = percentageOfCoresEnabled;
            Type = type;
        }
    }
}