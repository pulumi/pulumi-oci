// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetMaskingAnalyticsMaskingAnalyticsCollectionItemDimension;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMaskingAnalyticsMaskingAnalyticsCollectionItem {
    /**
     * @return The total count for the aggregation metric.
     * 
     */
    private String count;
    /**
     * @return The scope of analytics data.
     * 
     */
    private List<GetMaskingAnalyticsMaskingAnalyticsCollectionItemDimension> dimensions;
    /**
     * @return The name of the aggregation metric.
     * 
     */
    private String metricName;

    private GetMaskingAnalyticsMaskingAnalyticsCollectionItem() {}
    /**
     * @return The total count for the aggregation metric.
     * 
     */
    public String count() {
        return this.count;
    }
    /**
     * @return The scope of analytics data.
     * 
     */
    public List<GetMaskingAnalyticsMaskingAnalyticsCollectionItemDimension> dimensions() {
        return this.dimensions;
    }
    /**
     * @return The name of the aggregation metric.
     * 
     */
    public String metricName() {
        return this.metricName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMaskingAnalyticsMaskingAnalyticsCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String count;
        private List<GetMaskingAnalyticsMaskingAnalyticsCollectionItemDimension> dimensions;
        private String metricName;
        public Builder() {}
        public Builder(GetMaskingAnalyticsMaskingAnalyticsCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.count = defaults.count;
    	      this.dimensions = defaults.dimensions;
    	      this.metricName = defaults.metricName;
        }

        @CustomType.Setter
        public Builder count(String count) {
            this.count = Objects.requireNonNull(count);
            return this;
        }
        @CustomType.Setter
        public Builder dimensions(List<GetMaskingAnalyticsMaskingAnalyticsCollectionItemDimension> dimensions) {
            this.dimensions = Objects.requireNonNull(dimensions);
            return this;
        }
        public Builder dimensions(GetMaskingAnalyticsMaskingAnalyticsCollectionItemDimension... dimensions) {
            return dimensions(List.of(dimensions));
        }
        @CustomType.Setter
        public Builder metricName(String metricName) {
            this.metricName = Objects.requireNonNull(metricName);
            return this;
        }
        public GetMaskingAnalyticsMaskingAnalyticsCollectionItem build() {
            final var o = new GetMaskingAnalyticsMaskingAnalyticsCollectionItem();
            o.count = count;
            o.dimensions = dimensions;
            o.metricName = metricName;
            return o;
        }
    }
}