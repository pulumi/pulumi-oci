// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetSecurityAssessmentFindingsFindingResult
    {
        /// <summary>
        /// The OCID of the assessment that generated this finding.
        /// </summary>
        public readonly string AssessmentId;
        /// <summary>
        /// The details of the finding. Provides detailed information to explain the finding summary, typically results from the assessed database, followed by any recommendations for changes.
        /// </summary>
        public readonly ImmutableArray<string> Details;
        /// <summary>
        /// The unique finding key. This is a system-generated identifier. To get the finding key for a finding, use ListFindings.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// Provides information on whether the finding is related to a CIS Oracle Database Benchmark recommendation, a STIG rule, or a GDPR Article/Recital.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentFindingsFindingReferenceResult> References;
        /// <summary>
        /// The explanation of the issue in this finding. It explains the reason for the rule and, if a risk is reported, it may also explain the recommended actions for remediation.
        /// </summary>
        public readonly string Remarks;
        /// <summary>
        /// A filter to return only findings of a particular risk level.
        /// </summary>
        public readonly string Severity;
        /// <summary>
        /// The brief summary of the finding. When the finding is informational, the summary typically reports only the number of data elements that were examined.
        /// </summary>
        public readonly string Summary;
        /// <summary>
        /// The OCID of the target database.
        /// </summary>
        public readonly string TargetId;
        /// <summary>
        /// The short title for the finding.
        /// </summary>
        public readonly string Title;

        [OutputConstructor]
        private GetSecurityAssessmentFindingsFindingResult(
            string assessmentId,

            ImmutableArray<string> details,

            string key,

            ImmutableArray<Outputs.GetSecurityAssessmentFindingsFindingReferenceResult> references,

            string remarks,

            string severity,

            string summary,

            string targetId,

            string title)
        {
            AssessmentId = assessmentId;
            Details = details;
            Key = key;
            References = references;
            Remarks = remarks;
            Severity = severity;
            Summary = summary;
            TargetId = targetId;
            Title = title;
        }
    }
}