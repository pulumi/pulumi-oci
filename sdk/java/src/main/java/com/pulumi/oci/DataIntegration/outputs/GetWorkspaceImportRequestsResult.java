// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceImportRequestsFilter;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceImportRequestsImportRequestSummaryCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetWorkspaceImportRequestsResult {
    private @Nullable List<GetWorkspaceImportRequestsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of import_request_summary_collection.
     * 
     */
    private List<GetWorkspaceImportRequestsImportRequestSummaryCollection> importRequestSummaryCollections;
    private @Nullable String importStatus;
    /**
     * @return Name of the import request.
     * 
     */
    private @Nullable String name;
    private @Nullable String projection;
    /**
     * @return Time at which the request was completely processed.
     * 
     */
    private @Nullable String timeEndedInMillis;
    /**
     * @return Time at which the request started getting processed.
     * 
     */
    private @Nullable String timeStartedInMillis;
    private String workspaceId;

    private GetWorkspaceImportRequestsResult() {}
    public List<GetWorkspaceImportRequestsFilter> filters() {
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
     * @return The list of import_request_summary_collection.
     * 
     */
    public List<GetWorkspaceImportRequestsImportRequestSummaryCollection> importRequestSummaryCollections() {
        return this.importRequestSummaryCollections;
    }
    public Optional<String> importStatus() {
        return Optional.ofNullable(this.importStatus);
    }
    /**
     * @return Name of the import request.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    public Optional<String> projection() {
        return Optional.ofNullable(this.projection);
    }
    /**
     * @return Time at which the request was completely processed.
     * 
     */
    public Optional<String> timeEndedInMillis() {
        return Optional.ofNullable(this.timeEndedInMillis);
    }
    /**
     * @return Time at which the request started getting processed.
     * 
     */
    public Optional<String> timeStartedInMillis() {
        return Optional.ofNullable(this.timeStartedInMillis);
    }
    public String workspaceId() {
        return this.workspaceId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceImportRequestsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetWorkspaceImportRequestsFilter> filters;
        private String id;
        private List<GetWorkspaceImportRequestsImportRequestSummaryCollection> importRequestSummaryCollections;
        private @Nullable String importStatus;
        private @Nullable String name;
        private @Nullable String projection;
        private @Nullable String timeEndedInMillis;
        private @Nullable String timeStartedInMillis;
        private String workspaceId;
        public Builder() {}
        public Builder(GetWorkspaceImportRequestsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.importRequestSummaryCollections = defaults.importRequestSummaryCollections;
    	      this.importStatus = defaults.importStatus;
    	      this.name = defaults.name;
    	      this.projection = defaults.projection;
    	      this.timeEndedInMillis = defaults.timeEndedInMillis;
    	      this.timeStartedInMillis = defaults.timeStartedInMillis;
    	      this.workspaceId = defaults.workspaceId;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetWorkspaceImportRequestsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetWorkspaceImportRequestsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder importRequestSummaryCollections(List<GetWorkspaceImportRequestsImportRequestSummaryCollection> importRequestSummaryCollections) {
            this.importRequestSummaryCollections = Objects.requireNonNull(importRequestSummaryCollections);
            return this;
        }
        public Builder importRequestSummaryCollections(GetWorkspaceImportRequestsImportRequestSummaryCollection... importRequestSummaryCollections) {
            return importRequestSummaryCollections(List.of(importRequestSummaryCollections));
        }
        @CustomType.Setter
        public Builder importStatus(@Nullable String importStatus) {
            this.importStatus = importStatus;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder projection(@Nullable String projection) {
            this.projection = projection;
            return this;
        }
        @CustomType.Setter
        public Builder timeEndedInMillis(@Nullable String timeEndedInMillis) {
            this.timeEndedInMillis = timeEndedInMillis;
            return this;
        }
        @CustomType.Setter
        public Builder timeStartedInMillis(@Nullable String timeStartedInMillis) {
            this.timeStartedInMillis = timeStartedInMillis;
            return this;
        }
        @CustomType.Setter
        public Builder workspaceId(String workspaceId) {
            this.workspaceId = Objects.requireNonNull(workspaceId);
            return this;
        }
        public GetWorkspaceImportRequestsResult build() {
            final var o = new GetWorkspaceImportRequestsResult();
            o.filters = filters;
            o.id = id;
            o.importRequestSummaryCollections = importRequestSummaryCollections;
            o.importStatus = importStatus;
            o.name = name;
            o.projection = projection;
            o.timeEndedInMillis = timeEndedInMillis;
            o.timeStartedInMillis = timeStartedInMillis;
            o.workspaceId = workspaceId;
            return o;
        }
    }
}