// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentStatisticAdvisory;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentStatisticEvaluate;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentStatisticHighRisk;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentStatisticLowRisk;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentStatisticMediumRisk;
import com.pulumi.oci.DataSafe.outputs.GetSecurityAssessmentStatisticPass;
import java.lang.Integer;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSecurityAssessmentStatistic {
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    private List<GetSecurityAssessmentStatisticAdvisory> advisories;
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    private List<GetSecurityAssessmentStatisticEvaluate> evaluates;
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    private List<GetSecurityAssessmentStatisticHighRisk> highRisks;
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    private List<GetSecurityAssessmentStatisticLowRisk> lowRisks;
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    private List<GetSecurityAssessmentStatisticMediumRisk> mediumRisks;
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    private List<GetSecurityAssessmentStatisticPass> passes;
    /**
     * @return The total number of targets in this security assessment.
     * 
     */
    private Integer targetsCount;

    private GetSecurityAssessmentStatistic() {}
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    public List<GetSecurityAssessmentStatisticAdvisory> advisories() {
        return this.advisories;
    }
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    public List<GetSecurityAssessmentStatisticEvaluate> evaluates() {
        return this.evaluates;
    }
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    public List<GetSecurityAssessmentStatisticHighRisk> highRisks() {
        return this.highRisks;
    }
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    public List<GetSecurityAssessmentStatisticLowRisk> lowRisks() {
        return this.lowRisks;
    }
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    public List<GetSecurityAssessmentStatisticMediumRisk> mediumRisks() {
        return this.mediumRisks;
    }
    /**
     * @return Statistics showing the number of findings with a particular risk level for each category.
     * 
     */
    public List<GetSecurityAssessmentStatisticPass> passes() {
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

    public static Builder builder(GetSecurityAssessmentStatistic defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSecurityAssessmentStatisticAdvisory> advisories;
        private List<GetSecurityAssessmentStatisticEvaluate> evaluates;
        private List<GetSecurityAssessmentStatisticHighRisk> highRisks;
        private List<GetSecurityAssessmentStatisticLowRisk> lowRisks;
        private List<GetSecurityAssessmentStatisticMediumRisk> mediumRisks;
        private List<GetSecurityAssessmentStatisticPass> passes;
        private Integer targetsCount;
        public Builder() {}
        public Builder(GetSecurityAssessmentStatistic defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.advisories = defaults.advisories;
    	      this.evaluates = defaults.evaluates;
    	      this.highRisks = defaults.highRisks;
    	      this.lowRisks = defaults.lowRisks;
    	      this.mediumRisks = defaults.mediumRisks;
    	      this.passes = defaults.passes;
    	      this.targetsCount = defaults.targetsCount;
        }

        @CustomType.Setter
        public Builder advisories(List<GetSecurityAssessmentStatisticAdvisory> advisories) {
            this.advisories = Objects.requireNonNull(advisories);
            return this;
        }
        public Builder advisories(GetSecurityAssessmentStatisticAdvisory... advisories) {
            return advisories(List.of(advisories));
        }
        @CustomType.Setter
        public Builder evaluates(List<GetSecurityAssessmentStatisticEvaluate> evaluates) {
            this.evaluates = Objects.requireNonNull(evaluates);
            return this;
        }
        public Builder evaluates(GetSecurityAssessmentStatisticEvaluate... evaluates) {
            return evaluates(List.of(evaluates));
        }
        @CustomType.Setter
        public Builder highRisks(List<GetSecurityAssessmentStatisticHighRisk> highRisks) {
            this.highRisks = Objects.requireNonNull(highRisks);
            return this;
        }
        public Builder highRisks(GetSecurityAssessmentStatisticHighRisk... highRisks) {
            return highRisks(List.of(highRisks));
        }
        @CustomType.Setter
        public Builder lowRisks(List<GetSecurityAssessmentStatisticLowRisk> lowRisks) {
            this.lowRisks = Objects.requireNonNull(lowRisks);
            return this;
        }
        public Builder lowRisks(GetSecurityAssessmentStatisticLowRisk... lowRisks) {
            return lowRisks(List.of(lowRisks));
        }
        @CustomType.Setter
        public Builder mediumRisks(List<GetSecurityAssessmentStatisticMediumRisk> mediumRisks) {
            this.mediumRisks = Objects.requireNonNull(mediumRisks);
            return this;
        }
        public Builder mediumRisks(GetSecurityAssessmentStatisticMediumRisk... mediumRisks) {
            return mediumRisks(List.of(mediumRisks));
        }
        @CustomType.Setter
        public Builder passes(List<GetSecurityAssessmentStatisticPass> passes) {
            this.passes = Objects.requireNonNull(passes);
            return this;
        }
        public Builder passes(GetSecurityAssessmentStatisticPass... passes) {
            return passes(List.of(passes));
        }
        @CustomType.Setter
        public Builder targetsCount(Integer targetsCount) {
            this.targetsCount = Objects.requireNonNull(targetsCount);
            return this;
        }
        public GetSecurityAssessmentStatistic build() {
            final var o = new GetSecurityAssessmentStatistic();
            o.advisories = advisories;
            o.evaluates = evaluates;
            o.highRisks = highRisks;
            o.lowRisks = lowRisks;
            o.mediumRisks = mediumRisks;
            o.passes = passes;
            o.targetsCount = targetsCount;
            return o;
        }
    }
}