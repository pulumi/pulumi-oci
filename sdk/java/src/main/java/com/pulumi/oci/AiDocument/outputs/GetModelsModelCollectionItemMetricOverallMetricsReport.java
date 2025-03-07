// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiDocument.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.AiDocument.outputs.GetModelsModelCollectionItemMetricOverallMetricsReportConfidenceEntry;
import java.lang.Double;
import java.lang.Integer;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetModelsModelCollectionItemMetricOverallMetricsReport {
    /**
     * @return List of document classification confidence report.
     * 
     */
    private List<GetModelsModelCollectionItemMetricOverallMetricsReportConfidenceEntry> confidenceEntries;
    /**
     * @return Total test documents in the label.
     * 
     */
    private Integer documentCount;
    /**
     * @return Mean average precision under different thresholds
     * 
     */
    private Double meanAveragePrecision;

    private GetModelsModelCollectionItemMetricOverallMetricsReport() {}
    /**
     * @return List of document classification confidence report.
     * 
     */
    public List<GetModelsModelCollectionItemMetricOverallMetricsReportConfidenceEntry> confidenceEntries() {
        return this.confidenceEntries;
    }
    /**
     * @return Total test documents in the label.
     * 
     */
    public Integer documentCount() {
        return this.documentCount;
    }
    /**
     * @return Mean average precision under different thresholds
     * 
     */
    public Double meanAveragePrecision() {
        return this.meanAveragePrecision;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelsModelCollectionItemMetricOverallMetricsReport defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetModelsModelCollectionItemMetricOverallMetricsReportConfidenceEntry> confidenceEntries;
        private Integer documentCount;
        private Double meanAveragePrecision;
        public Builder() {}
        public Builder(GetModelsModelCollectionItemMetricOverallMetricsReport defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.confidenceEntries = defaults.confidenceEntries;
    	      this.documentCount = defaults.documentCount;
    	      this.meanAveragePrecision = defaults.meanAveragePrecision;
        }

        @CustomType.Setter
        public Builder confidenceEntries(List<GetModelsModelCollectionItemMetricOverallMetricsReportConfidenceEntry> confidenceEntries) {
            if (confidenceEntries == null) {
              throw new MissingRequiredPropertyException("GetModelsModelCollectionItemMetricOverallMetricsReport", "confidenceEntries");
            }
            this.confidenceEntries = confidenceEntries;
            return this;
        }
        public Builder confidenceEntries(GetModelsModelCollectionItemMetricOverallMetricsReportConfidenceEntry... confidenceEntries) {
            return confidenceEntries(List.of(confidenceEntries));
        }
        @CustomType.Setter
        public Builder documentCount(Integer documentCount) {
            if (documentCount == null) {
              throw new MissingRequiredPropertyException("GetModelsModelCollectionItemMetricOverallMetricsReport", "documentCount");
            }
            this.documentCount = documentCount;
            return this;
        }
        @CustomType.Setter
        public Builder meanAveragePrecision(Double meanAveragePrecision) {
            if (meanAveragePrecision == null) {
              throw new MissingRequiredPropertyException("GetModelsModelCollectionItemMetricOverallMetricsReport", "meanAveragePrecision");
            }
            this.meanAveragePrecision = meanAveragePrecision;
            return this;
        }
        public GetModelsModelCollectionItemMetricOverallMetricsReport build() {
            final var _resultValue = new GetModelsModelCollectionItemMetricOverallMetricsReport();
            _resultValue.confidenceEntries = confidenceEntries;
            _resultValue.documentCount = documentCount;
            _resultValue.meanAveragePrecision = meanAveragePrecision;
            return _resultValue;
        }
    }
}
