// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItemDimension;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItem {
    /**
     * @return The dimensions available for SQL firewall allow SQL analytics.
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
     * @return The dimensions available for SQL firewall allow SQL analytics.
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
            this.dimensions = Objects.requireNonNull(dimensions);
            return this;
        }
        public Builder dimensions(GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItemDimension... dimensions) {
            return dimensions(List.of(dimensions));
        }
        @CustomType.Setter
        public Builder sqlFirewallAllowedSqlAnalyticCount(String sqlFirewallAllowedSqlAnalyticCount) {
            this.sqlFirewallAllowedSqlAnalyticCount = Objects.requireNonNull(sqlFirewallAllowedSqlAnalyticCount);
            return this;
        }
        public GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItem build() {
            final var o = new GetSqlFirewallAllowedSqlAnalyticsSqlFirewallAllowedSqlAnalyticsCollectionItem();
            o.dimensions = dimensions;
            o.sqlFirewallAllowedSqlAnalyticCount = sqlFirewallAllowedSqlAnalyticCount;
            return o;
        }
    }
}