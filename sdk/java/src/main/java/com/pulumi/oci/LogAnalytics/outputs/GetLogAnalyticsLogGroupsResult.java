// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.LogAnalytics.outputs.GetLogAnalyticsLogGroupsFilter;
import com.pulumi.oci.LogAnalytics.outputs.GetLogAnalyticsLogGroupsLogAnalyticsLogGroupSummaryCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetLogAnalyticsLogGroupsResult {
    /**
     * @return Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private final String compartmentId;
    /**
     * @return A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
     * 
     */
    private final @Nullable String displayName;
    private final @Nullable List<GetLogAnalyticsLogGroupsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The list of log_analytics_log_group_summary_collection.
     * 
     */
    private final List<GetLogAnalyticsLogGroupsLogAnalyticsLogGroupSummaryCollection> logAnalyticsLogGroupSummaryCollections;
    private final String namespace;

    @CustomType.Constructor
    private GetLogAnalyticsLogGroupsResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("filters") @Nullable List<GetLogAnalyticsLogGroupsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("logAnalyticsLogGroupSummaryCollections") List<GetLogAnalyticsLogGroupsLogAnalyticsLogGroupSummaryCollection> logAnalyticsLogGroupSummaryCollections,
        @CustomType.Parameter("namespace") String namespace) {
        this.compartmentId = compartmentId;
        this.displayName = displayName;
        this.filters = filters;
        this.id = id;
        this.logAnalyticsLogGroupSummaryCollections = logAnalyticsLogGroupSummaryCollections;
        this.namespace = namespace;
    }

    /**
     * @return Compartment Identifier [OCID] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name that is changeable and that does not have to be unique. Format: a leading alphanumeric, followed by zero or more alphanumerics, underscores, spaces, backslashes, or hyphens in any order). No trailing spaces allowed.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetLogAnalyticsLogGroupsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of log_analytics_log_group_summary_collection.
     * 
     */
    public List<GetLogAnalyticsLogGroupsLogAnalyticsLogGroupSummaryCollection> logAnalyticsLogGroupSummaryCollections() {
        return this.logAnalyticsLogGroupSummaryCollections;
    }
    public String namespace() {
        return this.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLogAnalyticsLogGroupsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetLogAnalyticsLogGroupsFilter> filters;
        private String id;
        private List<GetLogAnalyticsLogGroupsLogAnalyticsLogGroupSummaryCollection> logAnalyticsLogGroupSummaryCollections;
        private String namespace;

        public Builder() {
    	      // Empty
        }

        public Builder(GetLogAnalyticsLogGroupsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.logAnalyticsLogGroupSummaryCollections = defaults.logAnalyticsLogGroupSummaryCollections;
    	      this.namespace = defaults.namespace;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder filters(@Nullable List<GetLogAnalyticsLogGroupsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetLogAnalyticsLogGroupsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder logAnalyticsLogGroupSummaryCollections(List<GetLogAnalyticsLogGroupsLogAnalyticsLogGroupSummaryCollection> logAnalyticsLogGroupSummaryCollections) {
            this.logAnalyticsLogGroupSummaryCollections = Objects.requireNonNull(logAnalyticsLogGroupSummaryCollections);
            return this;
        }
        public Builder logAnalyticsLogGroupSummaryCollections(GetLogAnalyticsLogGroupsLogAnalyticsLogGroupSummaryCollection... logAnalyticsLogGroupSummaryCollections) {
            return logAnalyticsLogGroupSummaryCollections(List.of(logAnalyticsLogGroupSummaryCollections));
        }
        public Builder namespace(String namespace) {
            this.namespace = Objects.requireNonNull(namespace);
            return this;
        }        public GetLogAnalyticsLogGroupsResult build() {
            return new GetLogAnalyticsLogGroupsResult(compartmentId, displayName, filters, id, logAnalyticsLogGroupSummaryCollections, namespace);
        }
    }
}
