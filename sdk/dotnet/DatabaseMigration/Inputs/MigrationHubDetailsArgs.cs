// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Inputs
{

    public sealed class MigrationHubDetailsArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) ODMS will monitor GoldenGate end-to-end latency until the lag time is lower than the specified value in seconds.
        /// </summary>
        [Input("acceptableLag")]
        public Input<int>? AcceptableLag { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the resource being referenced.
        /// </summary>
        [Input("computeId")]
        public Input<string>? ComputeId { get; set; }

        /// <summary>
        /// (Updatable) Parameters for GoldenGate Extract processes.
        /// </summary>
        [Input("extract")]
        public Input<Inputs.MigrationHubDetailsExtractArgs>? Extract { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the resource being referenced.
        /// </summary>
        [Input("keyId", required: true)]
        public Input<string> KeyId { get; set; } = null!;

        /// <summary>
        /// (Updatable) Parameters for GoldenGate Replicat processes.
        /// </summary>
        [Input("replicat")]
        public Input<Inputs.MigrationHubDetailsReplicatArgs>? Replicat { get; set; }

        /// <summary>
        /// (Updatable) Database Administrator Credentials details.
        /// </summary>
        [Input("restAdminCredentials", required: true)]
        public Input<Inputs.MigrationHubDetailsRestAdminCredentialsArgs> RestAdminCredentials { get; set; } = null!;

        /// <summary>
        /// (Updatable) Endpoint URL.
        /// </summary>
        [Input("url", required: true)]
        public Input<string> Url { get; set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the resource being referenced.
        /// </summary>
        [Input("vaultId", required: true)]
        public Input<string> VaultId { get; set; } = null!;

        public MigrationHubDetailsArgs()
        {
        }
        public static new MigrationHubDetailsArgs Empty => new MigrationHubDetailsArgs();
    }
}
