// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceExportRequestsExportRequestSummaryCollection;
import com.pulumi.oci.DataIntegration.outputs.GetWorkspaceExportRequestsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetWorkspaceExportRequestsResult {
    /**
     * @return The list of export_request_summary_collection.
     * 
     */
    private List<GetWorkspaceExportRequestsExportRequestSummaryCollection> exportRequestSummaryCollections;
    private @Nullable String exportStatus;
    private @Nullable List<GetWorkspaceExportRequestsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Name of the export request.
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

    private GetWorkspaceExportRequestsResult() {}
    /**
     * @return The list of export_request_summary_collection.
     * 
     */
    public List<GetWorkspaceExportRequestsExportRequestSummaryCollection> exportRequestSummaryCollections() {
        return this.exportRequestSummaryCollections;
    }
    public Optional<String> exportStatus() {
        return Optional.ofNullable(this.exportStatus);
    }
    public List<GetWorkspaceExportRequestsFilter> filters() {
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
     * @return Name of the export request.
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

    public static Builder builder(GetWorkspaceExportRequestsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetWorkspaceExportRequestsExportRequestSummaryCollection> exportRequestSummaryCollections;
        private @Nullable String exportStatus;
        private @Nullable List<GetWorkspaceExportRequestsFilter> filters;
        private String id;
        private @Nullable String name;
        private @Nullable String projection;
        private @Nullable String timeEndedInMillis;
        private @Nullable String timeStartedInMillis;
        private String workspaceId;
        public Builder() {}
        public Builder(GetWorkspaceExportRequestsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.exportRequestSummaryCollections = defaults.exportRequestSummaryCollections;
    	      this.exportStatus = defaults.exportStatus;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.projection = defaults.projection;
    	      this.timeEndedInMillis = defaults.timeEndedInMillis;
    	      this.timeStartedInMillis = defaults.timeStartedInMillis;
    	      this.workspaceId = defaults.workspaceId;
        }

        @CustomType.Setter
        public Builder exportRequestSummaryCollections(List<GetWorkspaceExportRequestsExportRequestSummaryCollection> exportRequestSummaryCollections) {
            this.exportRequestSummaryCollections = Objects.requireNonNull(exportRequestSummaryCollections);
            return this;
        }
        public Builder exportRequestSummaryCollections(GetWorkspaceExportRequestsExportRequestSummaryCollection... exportRequestSummaryCollections) {
            return exportRequestSummaryCollections(List.of(exportRequestSummaryCollections));
        }
        @CustomType.Setter
        public Builder exportStatus(@Nullable String exportStatus) {
            this.exportStatus = exportStatus;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetWorkspaceExportRequestsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetWorkspaceExportRequestsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
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
        public GetWorkspaceExportRequestsResult build() {
            final var o = new GetWorkspaceExportRequestsResult();
            o.exportRequestSummaryCollections = exportRequestSummaryCollections;
            o.exportStatus = exportStatus;
            o.filters = filters;
            o.id = id;
            o.name = name;
            o.projection = projection;
            o.timeEndedInMillis = timeEndedInMillis;
            o.timeStartedInMillis = timeStartedInMillis;
            o.workspaceId = workspaceId;
            return o;
        }
    }
}