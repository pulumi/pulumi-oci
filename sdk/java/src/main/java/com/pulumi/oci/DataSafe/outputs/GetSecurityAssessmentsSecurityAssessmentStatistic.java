// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentsSecurityAssessmentStatisticAdvisory;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentsSecurityAssessmentStatisticEvaluate;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentsSecurityAssessmentStatisticHighRisk;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentsSecurityAssessmentStatisticLowRisk;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentsSecurityAssessmentStatisticMediumRisk;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentsSecurityAssessmentStatisticPass;
import java.lang.Integer;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSecurityAssessmentsSecurityAssessmentStatistic {
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    private final List<GetSecurityAssessmentsSecurityAssessmentStatisticAdvisory> advisories;
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    private final List<GetSecurityAssessmentsSecurityAssessmentStatisticEvaluate> evaluates;
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    private final List<GetSecurityAssessmentsSecurityAssessmentStatisticHighRisk> highRisks;
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    private final List<GetSecurityAssessmentsSecurityAssessmentStatisticLowRisk> lowRisks;
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    private final List<GetSecurityAssessmentsSecurityAssessmentStatisticMediumRisk> mediumRisks;
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    private final List<GetSecurityAssessmentsSecurityAssessmentStatisticPass> passes;
    /**
     * @return The total number of targets in this security assessment.
     * 
     */
    private final Integer targetsCount;

    @CustomType.Constructor
    private GetSecurityAssessmentsSecurityAssessmentStatistic(
        @CustomType.Parameter("advisories") List<GetSecurityAssessmentsSecurityAssessmentStatisticAdvisory> advisories,
        @CustomType.Parameter("evaluates") List<GetSecurityAssessmentsSecurityAssessmentStatisticEvaluate> evaluates,
        @CustomType.Parameter("highRisks") List<GetSecurityAssessmentsSecurityAssessmentStatisticHighRisk> highRisks,
        @CustomType.Parameter("lowRisks") List<GetSecurityAssessmentsSecurityAssessmentStatisticLowRisk> lowRisks,
        @CustomType.Parameter("mediumRisks") List<GetSecurityAssessmentsSecurityAssessmentStatisticMediumRisk> mediumRisks,
        @CustomType.Parameter("passes") List<GetSecurityAssessmentsSecurityAssessmentStatisticPass> passes,
        @CustomType.Parameter("targetsCount") Integer targetsCount) {
        this.advisories = advisories;
        this.evaluates = evaluates;
        this.highRisks = highRisks;
        this.lowRisks = lowRisks;
        this.mediumRisks = mediumRisks;
        this.passes = passes;
        this.targetsCount = targetsCount;
    }

    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    public List<GetSecurityAssessmentsSecurityAssessmentStatisticAdvisory> advisories() {
        return this.advisories;
    }
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    public List<GetSecurityAssessmentsSecurityAssessmentStatisticEvaluate> evaluates() {
        return this.evaluates;
    }
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    public List<GetSecurityAssessmentsSecurityAssessmentStatisticHighRisk> highRisks() {
        return this.highRisks;
    }
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    public List<GetSecurityAssessmentsSecurityAssessmentStatisticLowRisk> lowRisks() {
        return this.lowRisks;
    }
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    public List<GetSecurityAssessmentsSecurityAssessmentStatisticMediumRisk> mediumRisks() {
        return this.mediumRisks;
    }
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    public List<GetSecurityAssessmentsSecurityAssessmentStatisticPass> passes() {
        return this.passes;
    }
    /**
     * @return The total number of targets in this security assessment.
     * 
     */
    public Integer targetsCount() {
        return this.targetsCount;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSecurityAssessmentsSecurityAssessmentStatistic defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetSecurityAssessmentsSecurityAssessmentStatisticAdvisory> advisories;
        private List<GetSecurityAssessmentsSecurityAssessmentStatisticEvaluate> evaluates;
        private List<GetSecurityAssessmentsSecurityAssessmentStatisticHighRisk> highRisks;
        private List<GetSecurityAssessmentsSecurityAssessmentStatisticLowRisk> lowRisks;
        private List<GetSecurityAssessmentsSecurityAssessmentStatisticMediumRisk> mediumRisks;
        private List<GetSecurityAssessmentsSecurityAssessmentStatisticPass> passes;
        private Integer targetsCount;

        public Builder() {
    	      // Empty
        }

        public Builder(GetSecurityAssessmentsSecurityAssessmentStatistic defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.advisories = defaults.advisories;
    	      this.evaluates = defaults.evaluates;
    	      this.highRisks = defaults.highRisks;
    	      this.lowRisks = defaults.lowRisks;
    	      this.mediumRisks = defaults.mediumRisks;
    	      this.passes = defaults.passes;
    	      this.targetsCount = defaults.targetsCount;
        }

        public Builder advisories(List<GetSecurityAssessmentsSecurityAssessmentStatisticAdvisory> advisories) {
            this.advisories = Objects.requireNonNull(advisories);
            return this;
        }
        public Builder advisories(GetSecurityAssessmentsSecurityAssessmentStatisticAdvisory... advisories) {
            return advisories(List.of(advisories));
        }
        public Builder evaluates(List<GetSecurityAssessmentsSecurityAssessmentStatisticEvaluate> evaluates) {
            this.evaluates = Objects.requireNonNull(evaluates);
            return this;
        }
        public Builder evaluates(GetSecurityAssessmentsSecurityAssessmentStatisticEvaluate... evaluates) {
            return evaluates(List.of(evaluates));
        }
        public Builder highRisks(List<GetSecurityAssessmentsSecurityAssessmentStatisticHighRisk> highRisks) {
            this.highRisks = Objects.requireNonNull(highRisks);
            return this;
        }
        public Builder highRisks(GetSecurityAssessmentsSecurityAssessmentStatisticHighRisk... highRisks) {
            return highRisks(List.of(highRisks));
        }
        public Builder lowRisks(List<GetSecurityAssessmentsSecurityAssessmentStatisticLowRisk> lowRisks) {
            this.lowRisks = Objects.requireNonNull(lowRisks);
            return this;
        }
        public Builder lowRisks(GetSecurityAssessmentsSecurityAssessmentStatisticLowRisk... lowRisks) {
            return lowRisks(List.of(lowRisks));
        }
        public Builder mediumRisks(List<GetSecurityAssessmentsSecurityAssessmentStatisticMediumRisk> mediumRisks) {
            this.mediumRisks = Objects.requireNonNull(mediumRisks);
            return this;
        }
        public Builder mediumRisks(GetSecurityAssessmentsSecurityAssessmentStatisticMediumRisk... mediumRisks) {
            return mediumRisks(List.of(mediumRisks));
        }
        public Builder passes(List<GetSecurityAssessmentsSecurityAssessmentStatisticPass> passes) {
            this.passes = Objects.requireNonNull(passes);
            return this;
        }
        public Builder passes(GetSecurityAssessmentsSecurityAssessmentStatisticPass... passes) {
            return passes(List.of(passes));
        }
        public Builder targetsCount(Integer targetsCount) {
            this.targetsCount = Objects.requireNonNull(targetsCount);
            return this;
        }        public GetSecurityAssessmentsSecurityAssessmentStatistic build() {
            return new GetSecurityAssessmentsSecurityAssessmentStatistic(advisories, evaluates, highRisks, lowRisks, mediumRisks, passes, targetsCount);
        }
    }
}
