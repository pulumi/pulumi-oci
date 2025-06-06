// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Outputs
{

    [OutputType]
    public sealed class GetMigrationGgsDetailResult
    {
        /// <summary>
        /// ODMS will monitor GoldenGate end-to-end latency until the lag time is lower than the specified value in seconds.
        /// </summary>
        public readonly int AcceptableLag;
        /// <summary>
        /// Parameters for Extract processes.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMigrationGgsDetailExtractResult> Extracts;
        /// <summary>
        /// Details about Oracle GoldenGate GGS Deployment.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMigrationGgsDetailGgsDeploymentResult> GgsDeployments;
        /// <summary>
        /// Parameters for Replicat processes.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMigrationGgsDetailReplicatResult> Replicats;

        [OutputConstructor]
        private GetMigrationGgsDetailResult(
            int acceptableLag,

            ImmutableArray<Outputs.GetMigrationGgsDetailExtractResult> extracts,

            ImmutableArray<Outputs.GetMigrationGgsDetailGgsDeploymentResult> ggsDeployments,

            ImmutableArray<Outputs.GetMigrationGgsDetailReplicatResult> replicats)
        {
            AcceptableLag = acceptableLag;
            Extracts = extracts;
            GgsDeployments = ggsDeployments;
            Replicats = replicats;
        }
    }
}
