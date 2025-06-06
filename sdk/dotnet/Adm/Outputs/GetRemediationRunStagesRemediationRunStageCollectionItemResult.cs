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
    public sealed class GetRemediationRunStagesRemediationRunStageCollectionItemResult
    {
        /// <summary>
        /// The Oracle Cloud identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the vulnerability audit.
        /// </summary>
        public readonly string AuditId;
        /// <summary>
        /// The next type of stage in the remediation run.
        /// </summary>
        public readonly string NextStageType;
        /// <summary>
        /// Pipeline properties which result from the run of the verify stage.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRemediationRunStagesRemediationRunStageCollectionItemPipelinePropertyResult> PipelineProperties;
        /// <summary>
        /// The previous type of stage in the remediation run.
        /// </summary>
        public readonly string PreviousStageType;
        /// <summary>
        /// Pull request properties from recommend stage of the remediation run.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRemediationRunStagesRemediationRunStageCollectionItemPullRequestPropertyResult> PullRequestProperties;
        /// <summary>
        /// Count of recommended application dependencies to update.
        /// </summary>
        public readonly int RecommendedUpdatesCount;
        /// <summary>
        /// Unique Remediation Run identifier path parameter.
        /// </summary>
        public readonly string RemediationRunId;
        /// <summary>
        /// A filter to return only Stages that match the specified status.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// Information about the current step within the stage.
        /// </summary>
        public readonly string Summary;
        /// <summary>
        /// The creation date and time of the remediation run stage (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time of the finish of the remediation run stage (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        public readonly string TimeFinished;
        /// <summary>
        /// The date and time of the start of the remediation run stage (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        public readonly string TimeStarted;
        /// <summary>
        /// A filter to return only Stages that match the specified type.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetRemediationRunStagesRemediationRunStageCollectionItemResult(
            string auditId,

            string nextStageType,

            ImmutableArray<Outputs.GetRemediationRunStagesRemediationRunStageCollectionItemPipelinePropertyResult> pipelineProperties,

            string previousStageType,

            ImmutableArray<Outputs.GetRemediationRunStagesRemediationRunStageCollectionItemPullRequestPropertyResult> pullRequestProperties,

            int recommendedUpdatesCount,

            string remediationRunId,

            string status,

            string summary,

            string timeCreated,

            string timeFinished,

            string timeStarted,

            string type)
        {
            AuditId = auditId;
            NextStageType = nextStageType;
            PipelineProperties = pipelineProperties;
            PreviousStageType = previousStageType;
            PullRequestProperties = pullRequestProperties;
            RecommendedUpdatesCount = recommendedUpdatesCount;
            RemediationRunId = remediationRunId;
            Status = status;
            Summary = summary;
            TimeCreated = timeCreated;
            TimeFinished = timeFinished;
            TimeStarted = timeStarted;
            Type = type;
        }
    }
}
