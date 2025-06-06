// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.outputs.GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItemDimension;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItem {
    /**
     * @return The dimensions available for SQL Firewall allow SQL analytics.
     * 
     */
    private List<GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItemDimension> dimensions;
    /**
     * @return The total count of the aggregated metric.
     * 
     */
    private String sqlFirewallAllowedSqlAnalyticCount;

    private GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItem() {}
    /**
     * @return The dimensions available for SQL Firewall allow SQL analytics.
     * 
     */
    public List<GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItemDimension> dimensions() {
        return this.dimensions;
    }
    /**
     * @return The total count of the aggregated metric.
     * 
     */
    public String sqlFirewallAllowedSqlAnalyticCount() {
        return this.sqlFirewallAllowedSqlAnalyticCount;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItemDimension> dimensions;
        private String sqlFirewallAllowedSqlAnalyticCount;
        public Builder() {}
        public Builder(GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dimensions = defaults.dimensions;
    	      this.sqlFirewallAllowedSqlAnalyticCount = defaults.sqlFirewallAllowedSqlAnalyticCount;
        }

        @CustomType.Setter
        public Builder dimensions(List<GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItemDimension> dimensions) {
            if (dimensions == null) {
              throw new MissingRequiredPropertyException("GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItem", "dimensions");
            }
            this.dimensions = dimensions;
            return this;
        }
        public Builder dimensions(GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItemDimension... dimensions) {
            return dimensions(List.of(dimensions));
        }
        @CustomType.Setter
        public Builder sqlFirewallAllowedSqlAnalyticCount(String sqlFirewallAllowedSqlAnalyticCount) {
            if (sqlFirewallAllowedSqlAnalyticCount == null) {
              throw new MissingRequiredPropertyException("GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItem", "sqlFirewallAllowedSqlAnalyticCount");
            }
            this.sqlFirewallAllowedSqlAnalyticCount = sqlFirewallAllowedSqlAnalyticCount;
            return this;
        }
        public GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItem build() {
            final var _resultValue = new GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItem();
            _resultValue.dimensions = dimensions;
            _resultValue.sqlFirewallAllowedSqlAnalyticCount = sqlFirewallAllowedSqlAnalyticCount;
            return _resultValue;
        }
    }
}
