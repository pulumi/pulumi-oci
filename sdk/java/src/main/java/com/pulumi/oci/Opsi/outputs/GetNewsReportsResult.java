// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Opsi.outputs.GetNewsReportsFilter;
import com.pulumi.oci.Opsi.outputs.GetNewsReportsNewsReportCollection;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetNewsReportsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private @Nullable String compartmentId;
    private @Nullable Boolean compartmentIdInSubtree;
    private @Nullable List<GetNewsReportsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of news_report_collection.
     * 
     */
    private List<GetNewsReportsNewsReportCollection> newsReportCollections;
    private @Nullable String newsReportId;
    /**
     * @return The current state of the news report.
     * 
     */
    private @Nullable List<String> states;
    /**
     * @return Indicates the status of a news report in Operations Insights.
     * 
     */
    private @Nullable List<String> statuses;

    private GetNewsReportsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }
    public List<GetNewsReportsFilter> filters() {
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
     * @return The list of news_report_collection.
     * 
     */
    public List<GetNewsReportsNewsReportCollection> newsReportCollections() {
        return this.newsReportCollections;
    }
    public Optional<String> newsReportId() {
        return Optional.ofNullable(this.newsReportId);
    }
    /**
     * @return The current state of the news report.
     * 
     */
    public List<String> states() {
        return this.states == null ? List.of() : this.states;
    }
    /**
     * @return Indicates the status of a news report in Operations Insights.
     * 
     */
    public List<String> statuses() {
        return this.statuses == null ? List.of() : this.statuses;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNewsReportsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable Boolean compartmentIdInSubtree;
        private @Nullable List<GetNewsReportsFilter> filters;
        private String id;
        private List<GetNewsReportsNewsReportCollection> newsReportCollections;
        private @Nullable String newsReportId;
        private @Nullable List<String> states;
        private @Nullable List<String> statuses;
        public Builder() {}
        public Builder(GetNewsReportsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.newsReportCollections = defaults.newsReportCollections;
    	      this.newsReportId = defaults.newsReportId;
    	      this.states = defaults.states;
    	      this.statuses = defaults.statuses;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentIdInSubtree(@Nullable Boolean compartmentIdInSubtree) {
            this.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetNewsReportsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetNewsReportsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder newsReportCollections(List<GetNewsReportsNewsReportCollection> newsReportCollections) {
            this.newsReportCollections = Objects.requireNonNull(newsReportCollections);
            return this;
        }
        public Builder newsReportCollections(GetNewsReportsNewsReportCollection... newsReportCollections) {
            return newsReportCollections(List.of(newsReportCollections));
        }
        @CustomType.Setter
        public Builder newsReportId(@Nullable String newsReportId) {
            this.newsReportId = newsReportId;
            return this;
        }
        @CustomType.Setter
        public Builder states(@Nullable List<String> states) {
            this.states = states;
            return this;
        }
        public Builder states(String... states) {
            return states(List.of(states));
        }
        @CustomType.Setter
        public Builder statuses(@Nullable List<String> statuses) {
            this.statuses = statuses;
            return this;
        }
        public Builder statuses(String... statuses) {
            return statuses(List.of(statuses));
        }
        public GetNewsReportsResult build() {
            final var o = new GetNewsReportsResult();
            o.compartmentId = compartmentId;
            o.compartmentIdInSubtree = compartmentIdInSubtree;
            o.filters = filters;
            o.id = id;
            o.newsReportCollections = newsReportCollections;
            o.newsReportId = newsReportId;
            o.states = states;
            o.statuses = statuses;
            return o;
        }
    }
}