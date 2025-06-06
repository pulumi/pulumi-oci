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
    public sealed class GetSecurityAssessmentsSecurityAssessmentStatisticResult
    {
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentsSecurityAssessmentStatisticAdvisoryResult> Advisories;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentsSecurityAssessmentStatisticDeferredResult> Deferreds;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentsSecurityAssessmentStatisticEvaluateResult> Evaluates;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentsSecurityAssessmentStatisticHighRiskResult> HighRisks;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentsSecurityAssessmentStatisticLowRiskResult> LowRisks;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentsSecurityAssessmentStatisticMediumRiskResult> MediumRisks;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityAssessmentsSecurityAssessmentStatisticPassResult> Passes;
        /// <summary>
        /// The total number of targets in this security assessment.
        /// </summary>
        public readonly int TargetsCount;

        [OutputConstructor]
        private GetSecurityAssessmentsSecurityAssessmentStatisticResult(
            ImmutableArray<Outputs.GetSecurityAssessmentsSecurityAssessmentStatisticAdvisoryResult> advisories,

            ImmutableArray<Outputs.GetSecurityAssessmentsSecurityAssessmentStatisticDeferredResult> deferreds,

            ImmutableArray<Outputs.GetSecurityAssessmentsSecurityAssessmentStatisticEvaluateResult> evaluates,

            ImmutableArray<Outputs.GetSecurityAssessmentsSecurityAssessmentStatisticHighRiskResult> highRisks,

            ImmutableArray<Outputs.GetSecurityAssessmentsSecurityAssessmentStatisticLowRiskResult> lowRisks,

            ImmutableArray<Outputs.GetSecurityAssessmentsSecurityAssessmentStatisticMediumRiskResult> mediumRisks,

            ImmutableArray<Outputs.GetSecurityAssessmentsSecurityAssessmentStatisticPassResult> passes,

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
