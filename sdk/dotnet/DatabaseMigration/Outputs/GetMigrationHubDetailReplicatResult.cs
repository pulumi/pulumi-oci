// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Outputs
{

    [OutputType]
    public sealed class GetMigrationHubDetailReplicatResult
    {
        /// <summary>
        /// Replicat performance.
        /// </summary>
        public readonly string PerformanceProfile;

        [OutputConstructor]
        private GetMigrationHubDetailReplicatResult(string performanceProfile)
        {
            PerformanceProfile = performanceProfile;
        }
    }
}
