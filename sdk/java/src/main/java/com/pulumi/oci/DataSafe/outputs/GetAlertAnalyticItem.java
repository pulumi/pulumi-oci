// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetAlertAnalyticItemDimension;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAlertAnalyticItem {
    /**
     * @return Total count of aggregated values.
     * 
     */
    private final String count;
    /**
     * @return Details of aggregation dimension summarizing alerts.
     * 
     */
    private final List<GetAlertAnalyticItemDimension> dimensions;
    /**
     * @return The name of the aggregation.
     * 
     */
    private final String metricName;
    /**
     * @return An optional filter to return audit events whose creation time in the database is less than and equal to the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private final String timeEnded;
    /**
     * @return An optional filter to return audit events whose creation time in the database is greater than and equal to the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private final String timeStarted;

    @CustomType.Constructor
    private GetAlertAnalyticItem(
        @CustomType.Parameter("count") String count,
        @CustomType.Parameter("dimensions") List<GetAlertAnalyticItemDimension> dimensions,
        @CustomType.Parameter("metricName") String metricName,
        @CustomType.Parameter("timeEnded") String timeEnded,
        @CustomType.Parameter("timeStarted") String timeStarted) {
        this.count = count;
        this.dimensions = dimensions;
        this.metricName = metricName;
        this.timeEnded = timeEnded;
        this.timeStarted = timeStarted;
    }

    /**
     * @return Total count of aggregated values.
     * 
     */
    public String count() {
        return this.count;
    }
    /**
     * @return Details of aggregation dimension summarizing alerts.
     * 
     */
    public List<GetAlertAnalyticItemDimension> dimensions() {
        return this.dimensions;
    }
    /**
     * @return The name of the aggregation.
     * 
     */
    public String metricName() {
        return this.metricName;
    }
    /**
     * @return An optional filter to return audit events whose creation time in the database is less than and equal to the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeEnded() {
        return this.timeEnded;
    }
    /**
     * @return An optional filter to return audit events whose creation time in the database is greater than and equal to the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeStarted() {
        return this.timeStarted;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAlertAnalyticItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String count;
        private List<GetAlertAnalyticItemDimension> dimensions;
        private String metricName;
        private String timeEnded;
        private String timeStarted;

        public Builder() {
    	      // Empty
        }

        public Builder(GetAlertAnalyticItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.count = defaults.count;
    	      this.dimensions = defaults.dimensions;
    	      this.metricName = defaults.metricName;
    	      this.timeEnded = defaults.timeEnded;
    	      this.timeStarted = defaults.timeStarted;
        }

        public Builder count(String count) {
            this.count = Objects.requireNonNull(count);
            return this;
        }
        public Builder dimensions(List<GetAlertAnalyticItemDimension> dimensions) {
            this.dimensions = Objects.requireNonNull(dimensions);
            return this;
        }
        public Builder dimensions(GetAlertAnalyticItemDimension... dimensions) {
            return dimensions(List.of(dimensions));
        }
        public Builder metricName(String metricName) {
            this.metricName = Objects.requireNonNull(metricName);
            return this;
        }
        public Builder timeEnded(String timeEnded) {
            this.timeEnded = Objects.requireNonNull(timeEnded);
            return this;
        }
        public Builder timeStarted(String timeStarted) {
            this.timeStarted = Objects.requireNonNull(timeStarted);
            return this;
        }        public GetAlertAnalyticItem build() {
            return new GetAlertAnalyticItem(count, dimensions, metricName, timeEnded, timeStarted);
        }
    }
}
