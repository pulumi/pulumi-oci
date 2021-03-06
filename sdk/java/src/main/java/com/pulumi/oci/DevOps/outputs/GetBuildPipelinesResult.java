// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetBuildPipelinesBuildPipelineCollection;
import com.pulumi.oci.DevOps.outputs.GetBuildPipelinesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetBuildPipelinesResult {
    /**
     * @return The list of build_pipeline_collection.
     * 
     */
    private final List<GetBuildPipelinesBuildPipelineCollection> buildPipelineCollections;
    /**
     * @return The OCID of the compartment where the build pipeline is created.
     * 
     */
    private final @Nullable String compartmentId;
    /**
     * @return Build pipeline display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    private final @Nullable String displayName;
    private final @Nullable List<GetBuildPipelinesFilter> filters;
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    private final @Nullable String id;
    /**
     * @return The OCID of the DevOps project.
     * 
     */
    private final @Nullable String projectId;
    /**
     * @return The current state of the build pipeline.
     * 
     */
    private final @Nullable String state;

    @CustomType.Constructor
    private GetBuildPipelinesResult(
        @CustomType.Parameter("buildPipelineCollections") List<GetBuildPipelinesBuildPipelineCollection> buildPipelineCollections,
        @CustomType.Parameter("compartmentId") @Nullable String compartmentId,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("filters") @Nullable List<GetBuildPipelinesFilter> filters,
        @CustomType.Parameter("id") @Nullable String id,
        @CustomType.Parameter("projectId") @Nullable String projectId,
        @CustomType.Parameter("state") @Nullable String state) {
        this.buildPipelineCollections = buildPipelineCollections;
        this.compartmentId = compartmentId;
        this.displayName = displayName;
        this.filters = filters;
        this.id = id;
        this.projectId = projectId;
        this.state = state;
    }

    /**
     * @return The list of build_pipeline_collection.
     * 
     */
    public List<GetBuildPipelinesBuildPipelineCollection> buildPipelineCollections() {
        return this.buildPipelineCollections;
    }
    /**
     * @return The OCID of the compartment where the build pipeline is created.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return Build pipeline display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetBuildPipelinesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The OCID of the DevOps project.
     * 
     */
    public Optional<String> projectId() {
        return Optional.ofNullable(this.projectId);
    }
    /**
     * @return The current state of the build pipeline.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBuildPipelinesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetBuildPipelinesBuildPipelineCollection> buildPipelineCollections;
        private @Nullable String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetBuildPipelinesFilter> filters;
        private @Nullable String id;
        private @Nullable String projectId;
        private @Nullable String state;

        public Builder() {
    	      // Empty
        }

        public Builder(GetBuildPipelinesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.buildPipelineCollections = defaults.buildPipelineCollections;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.projectId = defaults.projectId;
    	      this.state = defaults.state;
        }

        public Builder buildPipelineCollections(List<GetBuildPipelinesBuildPipelineCollection> buildPipelineCollections) {
            this.buildPipelineCollections = Objects.requireNonNull(buildPipelineCollections);
            return this;
        }
        public Builder buildPipelineCollections(GetBuildPipelinesBuildPipelineCollection... buildPipelineCollections) {
            return buildPipelineCollections(List.of(buildPipelineCollections));
        }
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder filters(@Nullable List<GetBuildPipelinesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetBuildPipelinesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        public Builder projectId(@Nullable String projectId) {
            this.projectId = projectId;
            return this;
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }        public GetBuildPipelinesResult build() {
            return new GetBuildPipelinesResult(buildPipelineCollections, compartmentId, displayName, filters, id, projectId, state);
        }
    }
}
