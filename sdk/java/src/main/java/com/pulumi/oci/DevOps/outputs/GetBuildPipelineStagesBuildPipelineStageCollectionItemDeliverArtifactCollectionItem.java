// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetBuildPipelineStagesBuildPipelineStageCollectionItemDeliverArtifactCollectionItem {
    /**
     * @return Artifact identifier that contains the artifact definition.
     * 
     */
    private String artifactId;
    /**
     * @return Name of the artifact specified in the build_spec.yaml file.
     * 
     */
    private String artifactName;

    private GetBuildPipelineStagesBuildPipelineStageCollectionItemDeliverArtifactCollectionItem() {}
    /**
     * @return Artifact identifier that contains the artifact definition.
     * 
     */
    public String artifactId() {
        return this.artifactId;
    }
    /**
     * @return Name of the artifact specified in the build_spec.yaml file.
     * 
     */
    public String artifactName() {
        return this.artifactName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBuildPipelineStagesBuildPipelineStageCollectionItemDeliverArtifactCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String artifactId;
        private String artifactName;
        public Builder() {}
        public Builder(GetBuildPipelineStagesBuildPipelineStageCollectionItemDeliverArtifactCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.artifactId = defaults.artifactId;
    	      this.artifactName = defaults.artifactName;
        }

        @CustomType.Setter
        public Builder artifactId(String artifactId) {
            if (artifactId == null) {
              throw new MissingRequiredPropertyException("GetBuildPipelineStagesBuildPipelineStageCollectionItemDeliverArtifactCollectionItem", "artifactId");
            }
            this.artifactId = artifactId;
            return this;
        }
        @CustomType.Setter
        public Builder artifactName(String artifactName) {
            if (artifactName == null) {
              throw new MissingRequiredPropertyException("GetBuildPipelineStagesBuildPipelineStageCollectionItemDeliverArtifactCollectionItem", "artifactName");
            }
            this.artifactName = artifactName;
            return this;
        }
        public GetBuildPipelineStagesBuildPipelineStageCollectionItemDeliverArtifactCollectionItem build() {
            final var _resultValue = new GetBuildPipelineStagesBuildPipelineStageCollectionItemDeliverArtifactCollectionItem();
            _resultValue.artifactId = artifactId;
            _resultValue.artifactName = artifactName;
            return _resultValue;
        }
    }
}
