// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetSecurityAssessmentStatisticResult
    {
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentStatisticAdvisoryResult> Advisories;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentStatisticDeferredResult> Deferreds;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentStatisticEvaluateResult> Evaluates;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentStatisticHighRiskResult> HighRisks;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentStatisticLowRiskResult> LowRisks;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentStatisticMediumRiskResult> MediumRisks;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentStatisticPassResult> Passes;
        /// <summary>
        /// The total number of targets in this security assessment.
        /// </summary>
        public readonly int TargetsCount;

        [OutputConstructor]
        private GetSecurityAssessmentStatisticResult(
            ImmutableArray<Outputs.GetSecurityAssessmentStatisticAdvisoryResult> advisories,

            ImmutableArray<Outputs.GetSecurityAssessmentStatisticDeferredResult> deferreds,

            ImmutableArray<Outputs.GetSecurityAssessmentStatisticEvaluateResult> evaluates,

            ImmutableArray<Outputs.GetSecurityAssessmentStatisticHighRiskResult> highRisks,

            ImmutableArray<Outputs.GetSecurityAssessmentStatisticLowRiskResult> lowRisks,

            ImmutableArray<Outputs.GetSecurityAssessmentStatisticMediumRiskResult> mediumRisks,

            ImmutableArray<Outputs.GetSecurityAssessmentStatisticPassResult> passes,

            int targetsCount)
        {
            Advisories = advisories;
            Deferreds = deferreds;
            Evaluates = evaluates;
            HighRisks = highRisks;
            LowRisks = lowRisks;
            MediumRisks = mediumRisks;
            Passes = passes;
            TargetsCount = targetsCount;
        }
    }
}
