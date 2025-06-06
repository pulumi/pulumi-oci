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
    public sealed class GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersionResult
    {
        /// <summary>
        /// A URL that points to a detailed description of the Autonomous Container Database version.
        /// </summary>
        public readonly string Details;
        /// <summary>
        /// The list of applications supported for the given version.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersionSupportedAppResult> SupportedApps;
        /// <summary>
        /// A valid Oracle Database version for provisioning an Autonomous Container Database.
        /// </summary>
        public readonly string Version;

        [OutputConstructor]
        private GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersionResult(
            string details,

            ImmutableArray<Outputs.GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersionSupportedAppResult> supportedApps,

            string version)
        {
            Details = details;
            SupportedApps = supportedApps;
            Version = version;
        }
    }
}
