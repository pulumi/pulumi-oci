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
    public sealed class MigrationGoldenGateDetails
    {
        /// <summary>
        /// (Updatable) Details about Oracle GoldenGate Microservices. Required for online logical migration.
        /// </summary>
        public readonly Outputs.MigrationGoldenGateDetailsHub Hub;
        /// <summary>
        /// (Updatable) Optional settings for GoldenGate Microservices processes
        /// </summary>
        public readonly Outputs.MigrationGoldenGateDetailsSettings? Settings;

        [OutputConstructor]
        private MigrationGoldenGateDetails(
            Outputs.MigrationGoldenGateDetailsHub hub,

            Outputs.MigrationGoldenGateDetailsSettings? settings)
        {
            Hub = hub;
            Settings = settings;
        }
    }
}
