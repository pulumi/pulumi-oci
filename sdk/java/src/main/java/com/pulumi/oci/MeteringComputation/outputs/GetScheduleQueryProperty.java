// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.MeteringComputation.outputs.GetScheduleQueryPropertyDateRange;
import com.pulumi.oci.MeteringComputation.outputs.GetScheduleQueryPropertyGroupByTag;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetScheduleQueryProperty {
    /**
     * @return The depth level of the compartment.
     * 
     */
    private Double compartmentDepth;
    /**
     * @return Static or dynamic date range `dateRangeType`, which corresponds with type-specific characteristics.
     * 
     */
    private List<GetScheduleQueryPropertyDateRange> dateRanges;
    /**
     * @return The filter object for query usage.
     * 
     */
    private String filter;
    /**
     * @return The usage granularity. DAILY - Daily data aggregation. MONTHLY - Monthly data aggregation.   Allowed values are: DAILY MONTHLY
     * 
     */
    private String granularity;
    /**
     * @return Aggregate the result by. For example: [ &#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34; ]
     * 
     */
    private List<String> groupBies;
    /**
     * @return GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only supports one tag in the list. For example: [ { &#34;namespace&#34;: &#34;oracle&#34;, &#34;key&#34;: &#34;createdBy&#34; ]
     * 
     */
    private List<GetScheduleQueryPropertyGroupByTag> groupByTags;
    /**
     * @return Specifies whether aggregated by time. If isAggregateByTime is true, all usage/cost over the query time period will be added up.
     * 
     */
    private Boolean isAggregateByTime;
    /**
     * @return The query usage type. COST by default if it is missing. Usage - Query the usage data. Cost - Query the cost/billing data.  Allowed values are: USAGE COST USAGE_AND_COST
     * 
     */
    private String queryType;

    private GetScheduleQueryProperty() {}
    /**
     * @return The depth level of the compartment.
     * 
     */
    public Double compartmentDepth() {
        return this.compartmentDepth;
    }
    /**
     * @return Static or dynamic date range `dateRangeType`, which corresponds with type-specific characteristics.
     * 
     */
    public List<GetScheduleQueryPropertyDateRange> dateRanges() {
        return this.dateRanges;
    }
    /**
     * @return The filter object for query usage.
     * 
     */
    public String filter() {
        return this.filter;
    }
    /**
     * @return The usage granularity. DAILY - Daily data aggregation. MONTHLY - Monthly data aggregation.   Allowed values are: DAILY MONTHLY
     * 
     */
    public String granularity() {
        return this.granularity;
    }
    /**
     * @return Aggregate the result by. For example: [ &#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34; ]
     * 
     */
    public List<String> groupBies() {
        return this.groupBies;
    }
    /**
     * @return GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only supports one tag in the list. For example: [ { &#34;namespace&#34;: &#34;oracle&#34;, &#34;key&#34;: &#34;createdBy&#34; ]
     * 
     */
    public List<GetScheduleQueryPropertyGroupByTag> groupByTags() {
        return this.groupByTags;
    }
    /**
     * @return Specifies whether aggregated by time. If isAggregateByTime is true, all usage/cost over the query time period will be added up.
     * 
     */
    public Boolean isAggregateByTime() {
        return this.isAggregateByTime;
    }
    /**
     * @return The query usage type. COST by default if it is missing. Usage - Query the usage data. Cost - Query the cost/billing data.  Allowed values are: USAGE COST USAGE_AND_COST
     * 
     */
    public String queryType() {
        return this.queryType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetScheduleQueryProperty defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Double compartmentDepth;
        private List<GetScheduleQueryPropertyDateRange> dateRanges;
        private String filter;
        private String granularity;
        private List<String> groupBies;
        private List<GetScheduleQueryPropertyGroupByTag> groupByTags;
        private Boolean isAggregateByTime;
        private String queryType;
        public Builder() {}
        public Builder(GetScheduleQueryProperty defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentDepth = defaults.compartmentDepth;
    	      this.dateRanges = defaults.dateRanges;
    	      this.filter = defaults.filter;
    	      this.granularity = defaults.granularity;
    	      this.groupBies = defaults.groupBies;
    	      this.groupByTags = defaults.groupByTags;
    	      this.isAggregateByTime = defaults.isAggregateByTime;
    	      this.queryType = defaults.queryType;
        }

        @CustomType.Setter
        public Builder compartmentDepth(Double compartmentDepth) {
            this.compartmentDepth = Objects.requireNonNull(compartmentDepth);
            return this;
        }
        @CustomType.Setter
        public Builder dateRanges(List<GetScheduleQueryPropertyDateRange> dateRanges) {
            this.dateRanges = Objects.requireNonNull(dateRanges);
            return this;
        }
        public Builder dateRanges(GetScheduleQueryPropertyDateRange... dateRanges) {
            return dateRanges(List.of(dateRanges));
        }
        @CustomType.Setter
        public Builder filter(String filter) {
            this.filter = Objects.requireNonNull(filter);
            return this;
        }
        @CustomType.Setter
        public Builder granularity(String granularity) {
            this.granularity = Objects.requireNonNull(granularity);
            return this;
        }
        @CustomType.Setter
        public Builder groupBies(List<String> groupBies) {
            this.groupBies = Objects.requireNonNull(groupBies);
            return this;
        }
        public Builder groupBies(String... groupBies) {
            return groupBies(List.of(groupBies));
        }
        @CustomType.Setter
        public Builder groupByTags(List<GetScheduleQueryPropertyGroupByTag> groupByTags) {
            this.groupByTags = Objects.requireNonNull(groupByTags);
            return this;
        }
        public Builder groupByTags(GetScheduleQueryPropertyGroupByTag... groupByTags) {
            return groupByTags(List.of(groupByTags));
        }
        @CustomType.Setter
        public Builder isAggregateByTime(Boolean isAggregateByTime) {
            this.isAggregateByTime = Objects.requireNonNull(isAggregateByTime);
            return this;
        }
        @CustomType.Setter
        public Builder queryType(String queryType) {
            this.queryType = Objects.requireNonNull(queryType);
            return this;
        }
        public GetScheduleQueryProperty build() {
            final var o = new GetScheduleQueryProperty();
            o.compartmentDepth = compartmentDepth;
            o.dateRanges = dateRanges;
            o.filter = filter;
            o.granularity = granularity;
            o.groupBies = groupBies;
            o.groupByTags = groupByTags;
            o.isAggregateByTime = isAggregateByTime;
            o.queryType = queryType;
            return o;
        }
    }
}