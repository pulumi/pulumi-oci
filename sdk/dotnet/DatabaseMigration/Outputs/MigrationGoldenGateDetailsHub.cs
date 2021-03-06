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
    public sealed class MigrationGoldenGateDetailsHub
    {
        /// <summary>
        /// (Updatable) OCID of GoldenGate Microservices compute instance.
        /// </summary>
        public readonly string? ComputeId;
        /// <summary>
        /// (Updatable) Database Administrator Credentials details.
        /// </summary>
        public readonly Outputs.MigrationGoldenGateDetailsHubRestAdminCredentials RestAdminCredentials;
        /// <summary>
        /// (Updatable) Database Administrator Credentials details.
        /// </summary>
        public readonly Outputs.MigrationGoldenGateDetailsHubSourceContainerDbAdminCredentials? SourceContainerDbAdminCredentials;
        /// <summary>
        /// (Updatable) Database Administrator Credentials details.
        /// </summary>
        public readonly Outputs.MigrationGoldenGateDetailsHubSourceDbAdminCredentials SourceDbAdminCredentials;
        /// <summary>
        /// (Updatable) Name of GoldenGate Microservices deployment to operate on source database
        /// </summary>
        public readonly string SourceMicroservicesDeploymentName;
        /// <summary>
        /// (Updatable) Database Administrator Credentials details.
        /// </summary>
        public readonly Outputs.MigrationGoldenGateDetailsHubTargetDbAdminCredentials TargetDbAdminCredentials;
        /// <summary>
        /// (Updatable) Name of GoldenGate Microservices deployment to operate on target database
        /// </summary>
        public readonly string TargetMicroservicesDeploymentName;
        /// <summary>
        /// (Updatable) Oracle GoldenGate Microservices hub's REST endpoint. Refer to https://docs.oracle.com/en/middleware/goldengate/core/19.1/securing/network.html#GUID-A709DA55-111D-455E-8942-C9BDD1E38CAA
        /// </summary>
        public readonly string Url;

        [OutputConstructor]
        private MigrationGoldenGateDetailsHub(
            string? computeId,

            Outputs.MigrationGoldenGateDetailsHubRestAdminCredentials restAdminCredentials,

            Outputs.MigrationGoldenGateDetailsHubSourceContainerDbAdminCredentials? sourceContainerDbAdminCredentials,

            Outputs.MigrationGoldenGateDetailsHubSourceDbAdminCredentials sourceDbAdminCredentials,

            string sourceMicroservicesDeploymentName,

            Outputs.MigrationGoldenGateDetailsHubTargetDbAdminCredentials targetDbAdminCredentials,

            string targetMicroservicesDeploymentName,

            string url)
        {
            ComputeId = computeId;
            RestAdminCredentials = restAdminCredentials;
            SourceContainerDbAdminCredentials = sourceContainerDbAdminCredentials;
            SourceDbAdminCredentials = sourceDbAdminCredentials;
            SourceMicroservicesDeploymentName = sourceMicroservicesDeploymentName;
            TargetDbAdminCredentials = targetDbAdminCredentials;
            TargetMicroservicesDeploymentName = targetMicroservicesDeploymentName;
            Url = url;
        }
    }
}
