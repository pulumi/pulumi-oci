// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetUserAssessmentComparisonSummaryBaseline;
import com.pulumi.oci.DataSafe.outputs.GetUserAssessmentComparisonSummaryCurrent;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetUserAssessmentComparisonSummary {
    private List<GetUserAssessmentComparisonSummaryBaseline> baselines;
    private List<GetUserAssessmentComparisonSummaryCurrent> currents;
    private String status;

    private GetUserAssessmentComparisonSummary() {}
    public List<GetUserAssessmentComparisonSummaryBaseline> baselines() {
        return this.baselines;
    }
    public List<GetUserAssessmentComparisonSummaryCurrent> currents() {
        return this.currents;
    }
    public String status() {
        return this.status;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetUserAssessmentComparisonSummary defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetUserAssessmentComparisonSummaryBaseline> baselines;
        private List<GetUserAssessmentComparisonSummaryCurrent> currents;
        private String status;
        public Builder() {}
        public Builder(GetUserAssessmentComparisonSummary defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.baselines = defaults.baselines;
    	      this.currents = defaults.currents;
    	      this.status = defaults.status;
        }

        @CustomType.Setter
        public Builder baselines(List<GetUserAssessmentComparisonSummaryBaseline> baselines) {
            this.baselines = Objects.requireNonNull(baselines);
            return this;
        }
        public Builder baselines(GetUserAssessmentComparisonSummaryBaseline... baselines) {
            return baselines(List.of(baselines));
        }
        @CustomType.Setter
        public Builder currents(List<GetUserAssessmentComparisonSummaryCurrent> currents) {
            this.currents = Objects.requireNonNull(currents);
            return this;
        }
        public Builder currents(GetUserAssessmentComparisonSummaryCurrent... currents) {
            return currents(List.of(currents));
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        public GetUserAssessmentComparisonSummary build() {
            final var o = new GetUserAssessmentComparisonSummary();
            o.baselines = baselines;
            o.currents = currents;
            o.status = status;
            return o;
        }
    }
}