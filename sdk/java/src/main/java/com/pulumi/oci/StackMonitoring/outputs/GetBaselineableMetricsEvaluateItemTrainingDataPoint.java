// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetBaselineableMetricsEvaluateItemTrainingDataPoint {
    /**
     * @return timestamp of when the metric was collected
     * 
     */
    private String timestamp;
    /**
     * @return value for the metric data point
     * 
     */
    private Double value;

    private GetBaselineableMetricsEvaluateItemTrainingDataPoint() {}
    /**
     * @return timestamp of when the metric was collected
     * 
     */
    public String timestamp() {
        return this.timestamp;
    }
    /**
     * @return value for the metric data point
     * 
     */
    public Double value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBaselineableMetricsEvaluateItemTrainingDataPoint defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String timestamp;
        private Double value;
        public Builder() {}
        public Builder(GetBaselineableMetricsEvaluateItemTrainingDataPoint defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.timestamp = defaults.timestamp;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder timestamp(String timestamp) {
            this.timestamp = Objects.requireNonNull(timestamp);
            return this;
        }
        @CustomType.Setter
        public Builder value(Double value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public GetBaselineableMetricsEvaluateItemTrainingDataPoint build() {
            final var o = new GetBaselineableMetricsEvaluateItemTrainingDataPoint();
            o.timestamp = timestamp;
            o.value = value;
            return o;
        }
    }
}