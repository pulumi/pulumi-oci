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
    public sealed class GetTargetAssetsTargetAssetCollectionItemEstimatedCostComputeResult
    {
        /// <summary>
        /// Total number of GPU
        /// </summary>
        public readonly double GpuCount;
        /// <summary>
        /// GPU per hour
        /// </summary>
        public readonly double GpuPerHour;
        /// <summary>
        /// GPU per hour by subscription
        /// </summary>
        public readonly double GpuPerHourBySubscription;
        /// <summary>
        /// Total usage of memory
        /// </summary>
        public readonly double MemoryAmountGb;
        /// <summary>
        /// Gigabyte per hour
        /// </summary>
        public readonly double MemoryGbPerHour;
        /// <summary>
        /// Gigabyte per hour by subscription
        /// </summary>
        public readonly double MemoryGbPerHourBySubscription;
        /// <summary>
        /// Total number of OCPUs
        /// </summary>
        public readonly double OcpuCount;
        /// <summary>
        /// OCPU per hour
        /// </summary>
        public readonly double OcpuPerHour;
        /// <summary>
        /// OCPU per hour by subscription
        /// </summary>
        public readonly double OcpuPerHourBySubscription;
        /// <summary>
        /// Total price per hour
        /// </summary>
        public readonly double TotalPerHour;
        /// <summary>
        /// Total price per hour by subscription
        /// </summary>
        public readonly double TotalPerHourBySubscription;

        [OutputConstructor]
        private GetTargetAssetsTargetAssetCollectionItemEstimatedCostComputeResult(
            double gpuCount,

            double gpuPerHour,

            double gpuPerHourBySubscription,

            double memoryAmountGb,

            double memoryGbPerHour,

            double memoryGbPerHourBySubscription,

            double ocpuCount,

            double ocpuPerHour,

            double ocpuPerHourBySubscription,

            double totalPerHour,

            double totalPerHourBySubscription)
        {
            GpuCount = gpuCount;
            GpuPerHour = gpuPerHour;
            GpuPerHourBySubscription = gpuPerHourBySubscription;
            MemoryAmountGb = memoryAmountGb;
            MemoryGbPerHour = memoryGbPerHour;
            MemoryGbPerHourBySubscription = memoryGbPerHourBySubscription;
            OcpuCount = ocpuCount;
            OcpuPerHour = ocpuPerHour;
            OcpuPerHourBySubscription = ocpuPerHourBySubscription;
            TotalPerHour = totalPerHour;
            TotalPerHourBySubscription = totalPerHourBySubscription;
        }
    }
}
