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
    public sealed class GetExascaleDbStorageVaultsExascaleDbStorageVaultHighCapacityDatabaseStorageResult
    {
        /// <summary>
        /// Available Capacity
        /// </summary>
        public readonly int AvailableSizeInGbs;
        /// <summary>
        /// Total Capacity
        /// </summary>
        public readonly int TotalSizeInGbs;

        [OutputConstructor]
        private GetExascaleDbStorageVaultsExascaleDbStorageVaultHighCapacityDatabaseStorageResult(
            int availableSizeInGbs,

            int totalSizeInGbs)
        {
            AvailableSizeInGbs = availableSizeInGbs;
            TotalSizeInGbs = totalSizeInGbs;
        }
    }
}
