// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;


public final class GetBaselineableMetricsEvaluateItemEvaluationDataPointArgs extends com.pulumi.resources.ResourceArgs {

    public static final GetBaselineableMetricsEvaluateItemEvaluationDataPointArgs Empty = new GetBaselineableMetricsEvaluateItemEvaluationDataPointArgs();

    /**
     * timestamp of when the metric was collected
     * 
     */
    @Import(name="timestamp", required=true)
    private Output<String> timestamp;

    /**
     * @return timestamp of when the metric was collected
     * 
     */
    public Output<String> timestamp() {
        return this.timestamp;
    }

    /**
     * value for the metric data point
     * 
     */
    @Import(name="value", required=true)
    private Output<Double> value;

    /**
     * @return value for the metric data point
     * 
     */
    public Output<Double> value() {
        return this.value;
    }

    private GetBaselineableMetricsEvaluateItemEvaluationDataPointArgs() {}

    private GetBaselineableMetricsEvaluateItemEvaluationDataPointArgs(GetBaselineableMetricsEvaluateItemEvaluationDataPointArgs $) {
        this.timestamp = $.timestamp;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBaselineableMetricsEvaluateItemEvaluationDataPointArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBaselineableMetricsEvaluateItemEvaluationDataPointArgs $;

        public Builder() {
            $ = new GetBaselineableMetricsEvaluateItemEvaluationDataPointArgs();
        }

        public Builder(GetBaselineableMetricsEvaluateItemEvaluationDataPointArgs defaults) {
            $ = new GetBaselineableMetricsEvaluateItemEvaluationDataPointArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param timestamp timestamp of when the metric was collected
         * 
         * @return builder
         * 
         */
        public Builder timestamp(Output<String> timestamp) {
            $.timestamp = timestamp;
            return this;
        }

        /**
         * @param timestamp timestamp of when the metric was collected
         * 
         * @return builder
         * 
         */
        public Builder timestamp(String timestamp) {
            return timestamp(Output.of(timestamp));
        }

        /**
         * @param value value for the metric data point
         * 
         * @return builder
         * 
         */
        public Builder value(Output<Double> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value value for the metric data point
         * 
         * @return builder
         * 
         */
        public Builder value(Double value) {
            return value(Output.of(value));
        }

        public GetBaselineableMetricsEvaluateItemEvaluationDataPointArgs build() {
            if ($.timestamp == null) {
                throw new MissingRequiredPropertyException("GetBaselineableMetricsEvaluateItemEvaluationDataPointArgs", "timestamp");
            }
            if ($.value == null) {
                throw new MissingRequiredPropertyException("GetBaselineableMetricsEvaluateItemEvaluationDataPointArgs", "value");
            }
            return $;
        }
    }

}
