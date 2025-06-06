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
    public sealed class GetDbSystemStoragePerformancesDbSystemStoragePerformanceDataStoragePerformanceListHighDiskPerformanceResult
    {
        /// <summary>
        /// Disk IOPS in thousands.
        /// </summary>
        public readonly double DiskIops;
        /// <summary>
        /// Disk Throughput in Mbps.
        /// </summary>
        public readonly double DiskThroughputInMbps;

        [OutputConstructor]
        private GetDbSystemStoragePerformancesDbSystemStoragePerformanceDataStoragePerformanceListHighDiskPerformanceResult(
            double diskIops,

            double diskThroughputInMbps)
        {
            DiskIops = diskIops;
            DiskThroughputInMbps = diskThroughputInMbps;
        }
    }
}
