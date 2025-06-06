// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Psql.Outputs
{

    [OutputType]
    public sealed class GetDbSystemManagementPolicyBackupPolicyCopyPolicyResult
    {
        /// <summary>
        /// target compartment to place a new backup
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// List of region names of the remote region
        /// </summary>
        public readonly ImmutableArray<string> Regions;
        /// <summary>
        /// Retention period in days of the backup copy.
        /// </summary>
        public readonly int RetentionPeriod;

        [OutputConstructor]
        private GetDbSystemManagementPolicyBackupPolicyCopyPolicyResult(
            string compartmentId,

            ImmutableArray<string> regions,

            int retentionPeriod)
        {
            CompartmentId = compartmentId;
            Regions = regions;
            RetentionPeriod = retentionPeriod;
        }
    }
}
