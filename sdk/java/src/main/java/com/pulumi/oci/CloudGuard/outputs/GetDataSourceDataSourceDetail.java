// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CloudGuard.outputs.GetDataSourceDataSourceDetailLoggingQueryDetail;
import com.pulumi.oci.CloudGuard.outputs.GetDataSourceDataSourceDetailQueryStartTime;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDataSourceDataSourceDetail {
    /**
     * @return The additional entities count used for data source query.
     * 
     */
    private Integer additionalEntitiesCount;
    /**
     * @return Possible type of dataSourceFeed Provider(LoggingQuery)
     * 
     */
    private String dataSourceFeedProvider;
    /**
     * @return Interval in minutes that query is run periodically.
     * 
     */
    private Integer intervalInMinutes;
    /**
     * @return Additional details specific to the data source type (Sighting/Insight).
     * 
     */
    private List<GetDataSourceDataSourceDetailLoggingQueryDetail> loggingQueryDetails;
    /**
     * @return Logging query type for data source (Sighting/Insight)
     * 
     */
    private String loggingQueryType;
    /**
     * @return Operator used in Data Soruce
     * 
     */
    private String operator;
    /**
     * @return The continuous query expression that is run periodically.
     * 
     */
    private String query;
    /**
     * @return Time when the query can start, if not specified it can start immediately.
     * 
     */
    private List<GetDataSourceDataSourceDetailQueryStartTime> queryStartTimes;
    /**
     * @return Logging Query regions
     * 
     */
    private List<String> regions;
    /**
     * @return The integer value that must be exceeded, fall below or equal to (depending on the operator), the query result to trigger an event.
     * 
     */
    private Integer threshold;

    private GetDataSourceDataSourceDetail() {}
    /**
     * @return The additional entities count used for data source query.
     * 
     */
    public Integer additionalEntitiesCount() {
        return this.additionalEntitiesCount;
    }
    /**
     * @return Possible type of dataSourceFeed Provider(LoggingQuery)
     * 
     */
    public String dataSourceFeedProvider() {
        return this.dataSourceFeedProvider;
    }
    /**
     * @return Interval in minutes that query is run periodically.
     * 
     */
    public Integer intervalInMinutes() {
        return this.intervalInMinutes;
    }
    /**
     * @return Additional details specific to the data source type (Sighting/Insight).
     * 
     */
    public List<GetDataSourceDataSourceDetailLoggingQueryDetail> loggingQueryDetails() {
        return this.loggingQueryDetails;
    }
    /**
     * @return Logging query type for data source (Sighting/Insight)
     * 
     */
    public String loggingQueryType() {
        return this.loggingQueryType;
    }
    /**
     * @return Operator used in Data Soruce
     * 
     */
    public String operator() {
        return this.operator;
    }
    /**
     * @return The continuous query expression that is run periodically.
     * 
     */
    public String query() {
        return this.query;
    }
    /**
     * @return Time when the query can start, if not specified it can start immediately.
     * 
     */
    public List<GetDataSourceDataSourceDetailQueryStartTime> queryStartTimes() {
        return this.queryStartTimes;
    }
    /**
     * @return Logging Query regions
     * 
     */
    public List<String> regions() {
        return this.regions;
    }
    /**
     * @return The integer value that must be exceeded, fall below or equal to (depending on the operator), the query result to trigger an event.
     * 
     */
    public Integer threshold() {
        return this.threshold;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDataSourceDataSourceDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer additionalEntitiesCount;
        private String dataSourceFeedProvider;
        private Integer intervalInMinutes;
        private List<GetDataSourceDataSourceDetailLoggingQueryDetail> loggingQueryDetails;
        private String loggingQueryType;
        private String operator;
        private String query;
        private List<GetDataSourceDataSourceDetailQueryStartTime> queryStartTimes;
        private List<String> regions;
        private Integer threshold;
        public Builder() {}
        public Builder(GetDataSourceDataSourceDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.additionalEntitiesCount = defaults.additionalEntitiesCount;
    	      this.dataSourceFeedProvider = defaults.dataSourceFeedProvider;
    	      this.intervalInMinutes = defaults.intervalInMinutes;
    	      this.loggingQueryDetails = defaults.loggingQueryDetails;
    	      this.loggingQueryType = defaults.loggingQueryType;
    	      this.operator = defaults.operator;
    	      this.query = defaults.query;
    	      this.queryStartTimes = defaults.queryStartTimes;
    	      this.regions = defaults.regions;
    	      this.threshold = defaults.threshold;
        }

        @CustomType.Setter
        public Builder additionalEntitiesCount(Integer additionalEntitiesCount) {
            this.additionalEntitiesCount = Objects.requireNonNull(additionalEntitiesCount);
            return this;
        }
        @CustomType.Setter
        public Builder dataSourceFeedProvider(String dataSourceFeedProvider) {
            this.dataSourceFeedProvider = Objects.requireNonNull(dataSourceFeedProvider);
            return this;
        }
        @CustomType.Setter
        public Builder intervalInMinutes(Integer intervalInMinutes) {
            this.intervalInMinutes = Objects.requireNonNull(intervalInMinutes);
            return this;
        }
        @CustomType.Setter
        public Builder loggingQueryDetails(List<GetDataSourceDataSourceDetailLoggingQueryDetail> loggingQueryDetails) {
            this.loggingQueryDetails = Objects.requireNonNull(loggingQueryDetails);
            return this;
        }
        public Builder loggingQueryDetails(GetDataSourceDataSourceDetailLoggingQueryDetail... loggingQueryDetails) {
            return loggingQueryDetails(List.of(loggingQueryDetails));
        }
        @CustomType.Setter
        public Builder loggingQueryType(String loggingQueryType) {
            this.loggingQueryType = Objects.requireNonNull(loggingQueryType);
            return this;
        }
        @CustomType.Setter
        public Builder operator(String operator) {
            this.operator = Objects.requireNonNull(operator);
            return this;
        }
        @CustomType.Setter
        public Builder query(String query) {
            this.query = Objects.requireNonNull(query);
            return this;
        }
        @CustomType.Setter
        public Builder queryStartTimes(List<GetDataSourceDataSourceDetailQueryStartTime> queryStartTimes) {
            this.queryStartTimes = Objects.requireNonNull(queryStartTimes);
            return this;
        }
        public Builder queryStartTimes(GetDataSourceDataSourceDetailQueryStartTime... queryStartTimes) {
            return queryStartTimes(List.of(queryStartTimes));
        }
        @CustomType.Setter
        public Builder regions(List<String> regions) {
            this.regions = Objects.requireNonNull(regions);
            return this;
        }
        public Builder regions(String... regions) {
            return regions(List.of(regions));
        }
        @CustomType.Setter
        public Builder threshold(Integer threshold) {
            this.threshold = Objects.requireNonNull(threshold);
            return this;
        }
        public GetDataSourceDataSourceDetail build() {
            final var o = new GetDataSourceDataSourceDetail();
            o.additionalEntitiesCount = additionalEntitiesCount;
            o.dataSourceFeedProvider = dataSourceFeedProvider;
            o.intervalInMinutes = intervalInMinutes;
            o.loggingQueryDetails = loggingQueryDetails;
            o.loggingQueryType = loggingQueryType;
            o.operator = operator;
            o.query = query;
            o.queryStartTimes = queryStartTimes;
            o.regions = regions;
            o.threshold = threshold;
            return o;
        }
    }
}