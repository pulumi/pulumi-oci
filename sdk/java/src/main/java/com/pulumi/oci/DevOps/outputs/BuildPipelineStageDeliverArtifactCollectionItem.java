// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class BuildPipelineStageDeliverArtifactCollectionItem {
    /**
     * @return (Updatable) Artifact identifier that contains the artifact definition.
     * 
     */
    private final @Nullable String artifactId;
    /**
     * @return (Updatable) Name of the artifact specified in the build_spec.yaml file.
     * 
     */
    private final @Nullable String artifactName;

    @CustomType.Constructor
    private BuildPipelineStageDeliverArtifactCollectionItem(
        @CustomType.Parameter("artifactId") @Nullable String artifactId,
        @CustomType.Parameter("artifactName") @Nullable String artifactName) {
        this.artifactId = artifactId;
        this.artifactName = artifactName;
    }

    /**
     * @return (Updatable) Artifact identifier that contains the artifact definition.
     * 
     */
    public Optional<String> artifactId() {
        return Optional.ofNullable(this.artifactId);
    }
    /**
     * @return (Updatable) Name of the artifact specified in the build_spec.yaml file.
     * 
     */
    public Optional<String> artifactName() {
        return Optional.ofNullable(this.artifactName);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(BuildPipelineStageDeliverArtifactCollectionItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String artifactId;
        private @Nullable String artifactName;

        public Builder() {
    	      // Empty
        }

        public Builder(BuildPipelineStageDeliverArtifactCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.artifactId = defaults.artifactId;
    	      this.artifactName = defaults.artifactName;
        }

        public Builder artifactId(@Nullable String artifactId) {
            this.artifactId = artifactId;
            return this;
        }
        public Builder artifactName(@Nullable String artifactName) {
            this.artifactName = artifactName;
            return this;
        }        public BuildPipelineStageDeliverArtifactCollectionItem build() {
            return new BuildPipelineStageDeliverArtifactCollectionItem(artifactId, artifactName);
        }
    }
}
