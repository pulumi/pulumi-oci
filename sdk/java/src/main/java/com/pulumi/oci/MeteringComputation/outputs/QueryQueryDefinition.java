// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.MeteringComputation.outputs.QueryQueryDefinitionCostAnalysisUi;
import com.pulumi.oci.MeteringComputation.outputs.QueryQueryDefinitionReportQuery;
import java.lang.Double;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class QueryQueryDefinition {
    /**
     * @return (Updatable) The common fields for Cost Analysis UI rendering.
     * 
     */
    private QueryQueryDefinitionCostAnalysisUi costAnalysisUi;
    /**
     * @return (Updatable) The query display name. Avoid entering confidential information.
     * 
     */
    private String displayName;
    /**
     * @return (Updatable) The request of the generated Cost Analysis report.
     * 
     */
    private QueryQueryDefinitionReportQuery reportQuery;
    /**
     * @return (Updatable) The saved query version.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private Double version;

    private QueryQueryDefinition() {}
    /**
     * @return (Updatable) The common fields for Cost Analysis UI rendering.
     * 
     */
    public QueryQueryDefinitionCostAnalysisUi costAnalysisUi() {
        return this.costAnalysisUi;
    }
    /**
     * @return (Updatable) The query display name. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return (Updatable) The request of the generated Cost Analysis report.
     * 
     */
    public QueryQueryDefinitionReportQuery reportQuery() {
        return this.reportQuery;
    }
    /**
     * @return (Updatable) The saved query version.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Double version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(QueryQueryDefinition defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private QueryQueryDefinitionCostAnalysisUi costAnalysisUi;
        private String displayName;
        private QueryQueryDefinitionReportQuery reportQuery;
        private Double version;
        public Builder() {}
        public Builder(QueryQueryDefinition defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.costAnalysisUi = defaults.costAnalysisUi;
    	      this.displayName = defaults.displayName;
    	      this.reportQuery = defaults.reportQuery;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder costAnalysisUi(QueryQueryDefinitionCostAnalysisUi costAnalysisUi) {
            if (costAnalysisUi == null) {
              throw new MissingRequiredPropertyException("QueryQueryDefinition", "costAnalysisUi");
            }
            this.costAnalysisUi = costAnalysisUi;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("QueryQueryDefinition", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder reportQuery(QueryQueryDefinitionReportQuery reportQuery) {
            if (reportQuery == null) {
              throw new MissingRequiredPropertyException("QueryQueryDefinition", "reportQuery");
            }
            this.reportQuery = reportQuery;
            return this;
        }
        @CustomType.Setter
        public Builder version(Double version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("QueryQueryDefinition", "version");
            }
            this.version = version;
            return this;
        }
        public QueryQueryDefinition build() {
            final var _resultValue = new QueryQueryDefinition();
            _resultValue.costAnalysisUi = costAnalysisUi;
            _resultValue.displayName = displayName;
            _resultValue.reportQuery = reportQuery;
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
