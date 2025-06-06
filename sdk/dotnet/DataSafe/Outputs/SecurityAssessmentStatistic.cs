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
    public sealed class SecurityAssessmentStatistic
    {
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.SecurityAssessmentStatisticAdvisory> Advisories;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.SecurityAssessmentStatisticDeferred> Deferreds;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.SecurityAssessmentStatisticEvaluate> Evaluates;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.SecurityAssessmentStatisticHighRisk> HighRisks;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.SecurityAssessmentStatisticLowRisk> LowRisks;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.SecurityAssessmentStatisticMediumRisk> MediumRisks;
        /// <summary>
        /// Statistics showing the number of findings with a particular risk level for each category.
        /// </summary>
        public readonly ImmutableArray<Outputs.SecurityAssessmentStatisticPass> Passes;
        /// <summary>
        /// The total number of targets in this security assessment.
        /// </summary>
        public readonly int? TargetsCount;

        [OutputConstructor]
        private SecurityAssessmentStatistic(
            ImmutableArray<Outputs.SecurityAssessmentStatisticAdvisory> advisories,

            ImmutableArray<Outputs.SecurityAssessmentStatisticDeferred> deferreds,

            ImmutableArray<Outputs.SecurityAssessmentStatisticEvaluate> evaluates,

            ImmutableArray<Outputs.SecurityAssessmentStatisticHighRisk> highRisks,

            ImmutableArray<Outputs.SecurityAssessmentStatisticLowRisk> lowRisks,

            ImmutableArray<Outputs.SecurityAssessmentStatisticMediumRisk> mediumRisks,

            ImmutableArray<Outputs.SecurityAssessmentStatisticPass> passes,

            int? targetsCount)
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
