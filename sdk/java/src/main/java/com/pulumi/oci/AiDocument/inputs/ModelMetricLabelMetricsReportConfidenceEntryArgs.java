// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Double;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ModelMetricLabelMetricsReportConfidenceEntryArgs extends com.pulumi.resources.ResourceArgs {

    public static final ModelMetricLabelMetricsReportConfidenceEntryArgs Empty = new ModelMetricLabelMetricsReportConfidenceEntryArgs();

    /**
     * accuracy under the threshold
     * 
     */
    @Import(name="accuracy")
    private @Nullable Output<Double> accuracy;

    /**
     * @return accuracy under the threshold
     * 
     */
    public Optional<Output<Double>> accuracy() {
        return Optional.ofNullable(this.accuracy);
    }

    /**
     * f1Score under the threshold
     * 
     */
    @Import(name="f1score")
    private @Nullable Output<Double> f1score;

    /**
     * @return f1Score under the threshold
     * 
     */
    public Optional<Output<Double>> f1score() {
        return Optional.ofNullable(this.f1score);
    }

    /**
     * Precision under the threshold
     * 
     */
    @Import(name="precision")
    private @Nullable Output<Double> precision;

    /**
     * @return Precision under the threshold
     * 
     */
    public Optional<Output<Double>> precision() {
        return Optional.ofNullable(this.precision);
    }

    /**
     * Recall under the threshold
     * 
     */
    @Import(name="recall")
    private @Nullable Output<Double> recall;

    /**
     * @return Recall under the threshold
     * 
     */
    public Optional<Output<Double>> recall() {
        return Optional.ofNullable(this.recall);
    }

    /**
     * Threshold used to calculate precision and recall.
     * 
     */
    @Import(name="threshold")
    private @Nullable Output<Double> threshold;

    /**
     * @return Threshold used to calculate precision and recall.
     * 
     */
    public Optional<Output<Double>> threshold() {
        return Optional.ofNullable(this.threshold);
    }

    private ModelMetricLabelMetricsReportConfidenceEntryArgs() {}

    private ModelMetricLabelMetricsReportConfidenceEntryArgs(ModelMetricLabelMetricsReportConfidenceEntryArgs $) {
        this.accuracy = $.accuracy;
        this.f1score = $.f1score;
        this.precision = $.precision;
        this.recall = $.recall;
        this.threshold = $.threshold;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ModelMetricLabelMetricsReportConfidenceEntryArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ModelMetricLabelMetricsReportConfidenceEntryArgs $;

        public Builder() {
            $ = new ModelMetricLabelMetricsReportConfidenceEntryArgs();
        }

        public Builder(ModelMetricLabelMetricsReportConfidenceEntryArgs defaults) {
            $ = new ModelMetricLabelMetricsReportConfidenceEntryArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param accuracy accuracy under the threshold
         * 
         * @return builder
         * 
         */
        public Builder accuracy(@Nullable Output<Double> accuracy) {
            $.accuracy = accuracy;
            return this;
        }

        /**
         * @param accuracy accuracy under the threshold
         * 
         * @return builder
         * 
         */
        public Builder accuracy(Double accuracy) {
            return accuracy(Output.of(accuracy));
        }

        /**
         * @param f1score f1Score under the threshold
         * 
         * @return builder
         * 
         */
        public Builder f1score(@Nullable Output<Double> f1score) {
            $.f1score = f1score;
            return this;
        }

        /**
         * @param f1score f1Score under the threshold
         * 
         * @return builder
         * 
         */
        public Builder f1score(Double f1score) {
            return f1score(Output.of(f1score));
        }

        /**
         * @param precision Precision under the threshold
         * 
         * @return builder
         * 
         */
        public Builder precision(@Nullable Output<Double> precision) {
            $.precision = precision;
            return this;
        }

        /**
         * @param precision Precision under the threshold
         * 
         * @return builder
         * 
         */
        public Builder precision(Double precision) {
            return precision(Output.of(precision));
        }

        /**
         * @param recall Recall under the threshold
         * 
         * @return builder
         * 
         */
        public Builder recall(@Nullable Output<Double> recall) {
            $.recall = recall;
            return this;
        }

        /**
         * @param recall Recall under the threshold
         * 
         * @return builder
         * 
         */
        public Builder recall(Double recall) {
            return recall(Output.of(recall));
        }

        /**
         * @param threshold Threshold used to calculate precision and recall.
         * 
         * @return builder
         * 
         */
        public Builder threshold(@Nullable Output<Double> threshold) {
            $.threshold = threshold;
            return this;
        }

        /**
         * @param threshold Threshold used to calculate precision and recall.
         * 
         * @return builder
         * 
         */
        public Builder threshold(Double threshold) {
            return threshold(Output.of(threshold));
        }

        public ModelMetricLabelMetricsReportConfidenceEntryArgs build() {
            return $;
        }
    }

}