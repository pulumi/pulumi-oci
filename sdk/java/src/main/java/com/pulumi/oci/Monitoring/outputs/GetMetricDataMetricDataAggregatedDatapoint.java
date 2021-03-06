// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Monitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMetricDataMetricDataAggregatedDatapoint {
    /**
     * @return The date and time associated with the value of this data point. Format defined by RFC3339.  Example: `2019-02-01T01:02:29.600Z`
     * 
     */
    private final String timestamp;
    /**
     * @return Numeric value of the metric.  Example: `10.4`
     * 
     */
    private final Double value;

    @CustomType.Constructor
    private GetMetricDataMetricDataAggregatedDatapoint(
        @CustomType.Parameter("timestamp") String timestamp,
        @CustomType.Parameter("value") Double value) {
        this.timestamp = timestamp;
        this.value = value;
    }

    /**
     * @return The date and time associated with the value of this data point. Format defined by RFC3339.  Example: `2019-02-01T01:02:29.600Z`
     * 
     */
    public String timestamp() {
        return this.timestamp;
    }
    /**
     * @return Numeric value of the metric.  Example: `10.4`
     * 
     */
    public Double value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMetricDataMetricDataAggregatedDatapoint defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String timestamp;
        private Double value;

        public Builder() {
    	      // Empty
        }

        public Builder(GetMetricDataMetricDataAggregatedDatapoint defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.timestamp = defaults.timestamp;
    	      this.value = defaults.value;
        }

        public Builder timestamp(String timestamp) {
            this.timestamp = Objects.requireNonNull(timestamp);
            return this;
        }
        public Builder value(Double value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }        public GetMetricDataMetricDataAggregatedDatapoint build() {
            return new GetMetricDataMetricDataAggregatedDatapoint(timestamp, value);
        }
    }
}
