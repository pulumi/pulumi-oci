// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetDeployArtifactsDeployArtifactCollection;
import com.pulumi.oci.DevOps.outputs.GetDeployArtifactsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDeployArtifactsResult {
    /**
     * @return The OCID of a compartment.
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return The list of deploy_artifact_collection.
     * 
     */
    private List<GetDeployArtifactsDeployArtifactCollection> deployArtifactCollections;
    /**
     * @return Deployment artifact identifier, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetDeployArtifactsFilter> filters;
    /**
     * @return Unique identifier that is immutable on creation.
     * 
     */
    private @Nullable String id;
    /**
     * @return The OCID of a project.
     * 
     */
    private @Nullable String projectId;
    /**
     * @return Current state of the deployment artifact.
     * 
     */
    private @Nullable String state;

    private GetDeployArtifactsResult() {}
    /**
     * @return The OCID of a compartment.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The list of deploy_artifact_collection.
     * 
     */
    public List<GetDeployArtifactsDeployArtifactCollection> deployArtifactCollections() {
        return this.deployArtifactCollections;
    }
    /**
     * @return Deployment artifact identifier, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetDeployArtifactsFilter> filters() {
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
     * @return The OCID of a project.
     * 
     */
    public Optional<String> projectId() {
        return Optional.ofNullable(this.projectId);
    }
    /**
     * @return Current state of the deployment artifact.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployArtifactsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private List<GetDeployArtifactsDeployArtifactCollection> deployArtifactCollections;
        private @Nullable String displayName;
        private @Nullable List<GetDeployArtifactsFilter> filters;
        private @Nullable String id;
        private @Nullable String projectId;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetDeployArtifactsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.deployArtifactCollections = defaults.deployArtifactCollections;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.projectId = defaults.projectId;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder deployArtifactCollections(List<GetDeployArtifactsDeployArtifactCollection> deployArtifactCollections) {
            this.deployArtifactCollections = Objects.requireNonNull(deployArtifactCollections);
            return this;
        }
        public Builder deployArtifactCollections(GetDeployArtifactsDeployArtifactCollection... deployArtifactCollections) {
            return deployArtifactCollections(List.of(deployArtifactCollections));
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDeployArtifactsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDeployArtifactsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder projectId(@Nullable String projectId) {
            this.projectId = projectId;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public GetDeployArtifactsResult build() {
            final var o = new GetDeployArtifactsResult();
            o.compartmentId = compartmentId;
            o.deployArtifactCollections = deployArtifactCollections;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.projectId = projectId;
            o.state = state;
            return o;
        }
    }
}