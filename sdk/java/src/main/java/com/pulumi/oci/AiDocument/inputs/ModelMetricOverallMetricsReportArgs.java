// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.AiDocument.inputs.ModelMetricOverallMetricsReportConfidenceEntryArgs;
import java.lang.Double;
import java.lang.Integer;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ModelMetricOverallMetricsReportArgs extends com.pulumi.resources.ResourceArgs {

    public static final ModelMetricOverallMetricsReportArgs Empty = new ModelMetricOverallMetricsReportArgs();

    /**
     * List of document classification confidence report.
     * 
     */
    @Import(name="confidenceEntries")
    private @Nullable Output<List<ModelMetricOverallMetricsReportConfidenceEntryArgs>> confidenceEntries;

    /**
     * @return List of document classification confidence report.
     * 
     */
    public Optional<Output<List<ModelMetricOverallMetricsReportConfidenceEntryArgs>>> confidenceEntries() {
        return Optional.ofNullable(this.confidenceEntries);
    }

    /**
     * Total test documents in the label.
     * 
     */
    @Import(name="documentCount")
    private @Nullable Output<Integer> documentCount;

    /**
     * @return Total test documents in the label.
     * 
     */
    public Optional<Output<Integer>> documentCount() {
        return Optional.ofNullable(this.documentCount);
    }

    /**
     * Mean average precision under different thresholds
     * 
     */
    @Import(name="meanAveragePrecision")
    private @Nullable Output<Double> meanAveragePrecision;

    /**
     * @return Mean average precision under different thresholds
     * 
     */
    public Optional<Output<Double>> meanAveragePrecision() {
        return Optional.ofNullable(this.meanAveragePrecision);
    }

    private ModelMetricOverallMetricsReportArgs() {}

    private ModelMetricOverallMetricsReportArgs(ModelMetricOverallMetricsReportArgs $) {
        this.confidenceEntries = $.confidenceEntries;
        this.documentCount = $.documentCount;
        this.meanAveragePrecision = $.meanAveragePrecision;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ModelMetricOverallMetricsReportArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ModelMetricOverallMetricsReportArgs $;

        public Builder() {
            $ = new ModelMetricOverallMetricsReportArgs();
        }

        public Builder(ModelMetricOverallMetricsReportArgs defaults) {
            $ = new ModelMetricOverallMetricsReportArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param confidenceEntries List of document classification confidence report.
         * 
         * @return builder
         * 
         */
        public Builder confidenceEntries(@Nullable Output<List<ModelMetricOverallMetricsReportConfidenceEntryArgs>> confidenceEntries) {
            $.confidenceEntries = confidenceEntries;
            return this;
        }

        /**
         * @param confidenceEntries List of document classification confidence report.
         * 
         * @return builder
         * 
         */
        public Builder confidenceEntries(List<ModelMetricOverallMetricsReportConfidenceEntryArgs> confidenceEntries) {
            return confidenceEntries(Output.of(confidenceEntries));
        }

        /**
         * @param confidenceEntries List of document classification confidence report.
         * 
         * @return builder
         * 
         */
        public Builder confidenceEntries(ModelMetricOverallMetricsReportConfidenceEntryArgs... confidenceEntries) {
            return confidenceEntries(List.of(confidenceEntries));
        }

        /**
         * @param documentCount Total test documents in the label.
         * 
         * @return builder
         * 
         */
        public Builder documentCount(@Nullable Output<Integer> documentCount) {
            $.documentCount = documentCount;
            return this;
        }

        /**
         * @param documentCount Total test documents in the label.
         * 
         * @return builder
         * 
         */
        public Builder documentCount(Integer documentCount) {
            return documentCount(Output.of(documentCount));
        }

        /**
         * @param meanAveragePrecision Mean average precision under different thresholds
         * 
         * @return builder
         * 
         */
        public Builder meanAveragePrecision(@Nullable Output<Double> meanAveragePrecision) {
            $.meanAveragePrecision = meanAveragePrecision;
            return this;
        }

        /**
         * @param meanAveragePrecision Mean average precision under different thresholds
         * 
         * @return builder
         * 
         */
        public Builder meanAveragePrecision(Double meanAveragePrecision) {
            return meanAveragePrecision(Output.of(meanAveragePrecision));
        }

        public ModelMetricOverallMetricsReportArgs build() {
            return $;
        }
    }

}
