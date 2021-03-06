// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetDiscoveryAnalyticItemDimension;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDiscoveryAnalyticItem {
    /**
     * @return The total count for the aggregation metric.
     * 
     */
    private final String count;
    /**
     * @return The scope of analytics data.
     * 
     */
    private final List<GetDiscoveryAnalyticItemDimension> dimensions;
    /**
     * @return The name of the aggregation metric.
     * 
     */
    private final String metricName;

    @CustomType.Constructor
    private GetDiscoveryAnalyticItem(
        @CustomType.Parameter("count") String count,
        @CustomType.Parameter("dimensions") List<GetDiscoveryAnalyticItemDimension> dimensions,
        @CustomType.Parameter("metricName") String metricName) {
        this.count = count;
        this.dimensions = dimensions;
        this.metricName = metricName;
    }

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
    public List<GetDiscoveryAnalyticItemDimension> dimensions() {
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

    public static Builder builder(GetDiscoveryAnalyticItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String count;
        private List<GetDiscoveryAnalyticItemDimension> dimensions;
        private String metricName;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDiscoveryAnalyticItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.count = defaults.count;
    	      this.dimensions = defaults.dimensions;
    	      this.metricName = defaults.metricName;
        }

        public Builder count(String count) {
            this.count = Objects.requireNonNull(count);
            return this;
        }
        public Builder dimensions(List<GetDiscoveryAnalyticItemDimension> dimensions) {
            this.dimensions = Objects.requireNonNull(dimensions);
            return this;
        }
        public Builder dimensions(GetDiscoveryAnalyticItemDimension... dimensions) {
            return dimensions(List.of(dimensions));
        }
        public Builder metricName(String metricName) {
            this.metricName = Objects.requireNonNull(metricName);
            return this;
        }        public GetDiscoveryAnalyticItem build() {
            return new GetDiscoveryAnalyticItem(count, dimensions, metricName);
        }
    }
}
