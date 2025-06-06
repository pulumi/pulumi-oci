// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FusionApps.Outputs
{

    [OutputType]
    public sealed class FusionEnvironmentRefresh
    {
        /// <summary>
        /// The source environment id for the last refresh
        /// </summary>
        public readonly string? SourceFusionEnvironmentId;
        /// <summary>
        /// The time of when the last refresh finish
        /// </summary>
        public readonly string? TimeFinished;
        /// <summary>
        /// The point of time of the latest DB backup for the last refresh
        /// </summary>
        public readonly string? TimeOfRestorationPoint;

        [OutputConstructor]
        private FusionEnvironmentRefresh(
            string? sourceFusionEnvironmentId,

            string? timeFinished,

            string? timeOfRestorationPoint)
        {
            SourceFusionEnvironmentId = sourceFusionEnvironmentId;
            TimeFinished = timeFinished;
            TimeOfRestorationPoint = timeOfRestorationPoint;
        }
    }
}
