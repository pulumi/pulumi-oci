// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;


public final class GetBaselineableMetricsEvaluateItemTrainingDataPoint extends com.pulumi.resources.InvokeArgs {

    public static final GetBaselineableMetricsEvaluateItemTrainingDataPoint Empty = new GetBaselineableMetricsEvaluateItemTrainingDataPoint();

    /**
     * timestamp of when the metric was collected
     * 
     */
    @Import(name="timestamp", required=true)
    private String timestamp;

    /**
     * @return timestamp of when the metric was collected
     * 
     */
    public String timestamp() {
        return this.timestamp;
    }

    /**
     * value for the metric data point
     * 
     */
    @Import(name="value", required=true)
    private Double value;

    /**
     * @return value for the metric data point
     * 
     */
    public Double value() {
        return this.value;
    }

    private GetBaselineableMetricsEvaluateItemTrainingDataPoint() {}

    private GetBaselineableMetricsEvaluateItemTrainingDataPoint(GetBaselineableMetricsEvaluateItemTrainingDataPoint $) {
        this.timestamp = $.timestamp;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBaselineableMetricsEvaluateItemTrainingDataPoint defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBaselineableMetricsEvaluateItemTrainingDataPoint $;

        public Builder() {
            $ = new GetBaselineableMetricsEvaluateItemTrainingDataPoint();
        }

        public Builder(GetBaselineableMetricsEvaluateItemTrainingDataPoint defaults) {
            $ = new GetBaselineableMetricsEvaluateItemTrainingDataPoint(Objects.requireNonNull(defaults));
        }

        /**
         * @param timestamp timestamp of when the metric was collected
         * 
         * @return builder
         * 
         */
        public Builder timestamp(String timestamp) {
            $.timestamp = timestamp;
            return this;
        }

        /**
         * @param value value for the metric data point
         * 
         * @return builder
         * 
         */
        public Builder value(Double value) {
            $.value = value;
            return this;
        }

        public GetBaselineableMetricsEvaluateItemTrainingDataPoint build() {
            $.timestamp = Objects.requireNonNull($.timestamp, "expected parameter 'timestamp' to be non-null");
            $.value = Objects.requireNonNull($.value, "expected parameter 'value' to be non-null");
            return $;
        }
    }

}