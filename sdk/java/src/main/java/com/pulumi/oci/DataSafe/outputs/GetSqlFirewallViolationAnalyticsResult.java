// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetSqlFirewallViolationAnalyticsFilter;
import com.pulumi.oci.DataSafe.outputs.GetSqlFirewallViolationAnalyticsSqlFirewallViolationAnalyticsCollection;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSqlFirewallViolationAnalyticsResult {
    private @Nullable String accessLevel;
    private String compartmentId;
    private @Nullable Boolean compartmentIdInSubtree;
    private @Nullable List<GetSqlFirewallViolationAnalyticsFilter> filters;
    private @Nullable List<String> groupBies;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable String queryTimeZone;
    private @Nullable String scimQuery;
    /**
     * @return The list of sql_firewall_violation_analytics_collection.
     * 
     */
    private List<GetSqlFirewallViolationAnalyticsSqlFirewallViolationAnalyticsCollection> sqlFirewallViolationAnalyticsCollections;
    private @Nullable List<String> summaryFields;
    /**
     * @return The time at which the aggregation ended.
     * 
     */
    private @Nullable String timeEnded;
    /**
     * @return The time at which the aggregation started.
     * 
     */
    private @Nullable String timeStarted;

    private GetSqlFirewallViolationAnalyticsResult() {}
    public Optional<String> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }
    public String compartmentId() {
        return this.compartmentId;
    }
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }
    public List<GetSqlFirewallViolationAnalyticsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    public List<String> groupBies() {
        return this.groupBies == null ? List.of() : this.groupBies;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> queryTimeZone() {
        return Optional.ofNullable(this.queryTimeZone);
    }
    public Optional<String> scimQuery() {
        return Optional.ofNullable(this.scimQuery);
    }
    /**
     * @return The list of sql_firewall_violation_analytics_collection.
     * 
     */
    public List<GetSqlFirewallViolationAnalyticsSqlFirewallViolationAnalyticsCollection> sqlFirewallViolationAnalyticsCollections() {
        return this.sqlFirewallViolationAnalyticsCollections;
    }
    public List<String> summaryFields() {
        return this.summaryFields == null ? List.of() : this.summaryFields;
    }
    /**
     * @return The time at which the aggregation ended.
     * 
     */
    public Optional<String> timeEnded() {
        return Optional.ofNullable(this.timeEnded);
    }
    /**
     * @return The time at which the aggregation started.
     * 
     */
    public Optional<String> timeStarted() {
        return Optional.ofNullable(this.timeStarted);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSqlFirewallViolationAnalyticsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String accessLevel;
        private String compartmentId;
        private @Nullable Boolean compartmentIdInSubtree;
        private @Nullable List<GetSqlFirewallViolationAnalyticsFilter> filters;
        private @Nullable List<String> groupBies;
        private String id;
        private @Nullable String queryTimeZone;
        private @Nullable String scimQuery;
        private List<GetSqlFirewallViolationAnalyticsSqlFirewallViolationAnalyticsCollection> sqlFirewallViolationAnalyticsCollections;
        private @Nullable List<String> summaryFields;
        private @Nullable String timeEnded;
        private @Nullable String timeStarted;
        public Builder() {}
        public Builder(GetSqlFirewallViolationAnalyticsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessLevel = defaults.accessLevel;
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.filters = defaults.filters;
    	      this.groupBies = defaults.groupBies;
    	      this.id = defaults.id;
    	      this.queryTimeZone = defaults.queryTimeZone;
    	      this.scimQuery = defaults.scimQuery;
    	      this.sqlFirewallViolationAnalyticsCollections = defaults.sqlFirewallViolationAnalyticsCollections;
    	      this.summaryFields = defaults.summaryFields;
    	      this.timeEnded = defaults.timeEnded;
    	      this.timeStarted = defaults.timeStarted;
        }

        @CustomType.Setter
        public Builder accessLevel(@Nullable String accessLevel) {
            this.accessLevel = accessLevel;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder compartmentIdInSubtree(@Nullable Boolean compartmentIdInSubtree) {
            this.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetSqlFirewallViolationAnalyticsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetSqlFirewallViolationAnalyticsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder groupBies(@Nullable List<String> groupBies) {
            this.groupBies = groupBies;
            return this;
        }
        public Builder groupBies(String... groupBies) {
            return groupBies(List.of(groupBies));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder queryTimeZone(@Nullable String queryTimeZone) {
            this.queryTimeZone = queryTimeZone;
            return this;
        }
        @CustomType.Setter
        public Builder scimQuery(@Nullable String scimQuery) {
            this.scimQuery = scimQuery;
            return this;
        }
        @CustomType.Setter
        public Builder sqlFirewallViolationAnalyticsCollections(List<GetSqlFirewallViolationAnalyticsSqlFirewallViolationAnalyticsCollection> sqlFirewallViolationAnalyticsCollections) {
            this.sqlFirewallViolationAnalyticsCollections = Objects.requireNonNull(sqlFirewallViolationAnalyticsCollections);
            return this;
        }
        public Builder sqlFirewallViolationAnalyticsCollections(GetSqlFirewallViolationAnalyticsSqlFirewallViolationAnalyticsCollection... sqlFirewallViolationAnalyticsCollections) {
            return sqlFirewallViolationAnalyticsCollections(List.of(sqlFirewallViolationAnalyticsCollections));
        }
        @CustomType.Setter
        public Builder summaryFields(@Nullable List<String> summaryFields) {
            this.summaryFields = summaryFields;
            return this;
        }
        public Builder summaryFields(String... summaryFields) {
            return summaryFields(List.of(summaryFields));
        }
        @CustomType.Setter
        public Builder timeEnded(@Nullable String timeEnded) {
            this.timeEnded = timeEnded;
            return this;
        }
        @CustomType.Setter
        public Builder timeStarted(@Nullable String timeStarted) {
            this.timeStarted = timeStarted;
            return this;
        }
        public GetSqlFirewallViolationAnalyticsResult build() {
            final var o = new GetSqlFirewallViolationAnalyticsResult();
            o.accessLevel = accessLevel;
            o.compartmentId = compartmentId;
            o.compartmentIdInSubtree = compartmentIdInSubtree;
            o.filters = filters;
            o.groupBies = groupBies;
            o.id = id;
            o.queryTimeZone = queryTimeZone;
            o.scimQuery = scimQuery;
            o.sqlFirewallViolationAnalyticsCollections = sqlFirewallViolationAnalyticsCollections;
            o.summaryFields = summaryFields;
            o.timeEnded = timeEnded;
            o.timeStarted = timeStarted;
            return o;
        }
    }
}