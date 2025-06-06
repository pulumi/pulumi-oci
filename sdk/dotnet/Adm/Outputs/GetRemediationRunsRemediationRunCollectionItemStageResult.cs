// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Adm.Outputs
{

    [OutputType]
    public sealed class GetRemediationRunsRemediationRunCollectionItemStageResult
    {
        /// <summary>
        /// Information about the current step within the given stage.
        /// </summary>
        public readonly string Summary;
        /// <summary>
        /// The creation date and time of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time of the finish of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        public readonly string TimeFinished;
        /// <summary>
        /// The date and time of the start of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        public readonly string TimeStarted;
        /// <summary>
        /// The type of stage.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetRemediationRunsRemediationRunCollectionItemStageResult(
            string summary,

            string timeCreated,

            string timeFinished,

            string timeStarted,

            string type)
        {
            Summary = summary;
            TimeCreated = timeCreated;
            TimeFinished = timeFinished;
            TimeStarted = timeStarted;
            Type = type;
        }
    }
}
