// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class GetBuildRunsBuildRunSummaryCollectionItemBuildRunProgressSummaryResult
    {
        /// <summary>
        /// The time the build run finished. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        public readonly string TimeFinished;
        /// <summary>
        /// The time the build run started. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
        /// </summary>
        public readonly string TimeStarted;

        [OutputConstructor]
        private GetBuildRunsBuildRunSummaryCollectionItemBuildRunProgressSummaryResult(
            string timeFinished,

            string timeStarted)
        {
            TimeFinished = timeFinished;
            TimeStarted = timeStarted;
        }
    }
}
