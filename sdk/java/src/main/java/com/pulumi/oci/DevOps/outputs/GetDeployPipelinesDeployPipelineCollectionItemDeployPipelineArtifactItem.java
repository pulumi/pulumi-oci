// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineArtifactItemDeployPipelineStage;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineArtifactItem {
    /**
     * @return The OCID of an artifact
     * 
     */
    private String deployArtifactId;
    /**
     * @return List of stages.
     * 
     */
    private List<GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineArtifactItemDeployPipelineStage> deployPipelineStages;
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private String displayName;

    private GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineArtifactItem() {}
    /**
     * @return The OCID of an artifact
     * 
     */
    public String deployArtifactId() {
        return this.deployArtifactId;
    }
    /**
     * @return List of stages.
     * 
     */
    public List<GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineArtifactItemDeployPipelineStage> deployPipelineStages() {
        return this.deployPipelineStages;
    }
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineArtifactItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String deployArtifactId;
        private List<GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineArtifactItemDeployPipelineStage> deployPipelineStages;
        private String displayName;
        public Builder() {}
        public Builder(GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineArtifactItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.deployArtifactId = defaults.deployArtifactId;
    	      this.deployPipelineStages = defaults.deployPipelineStages;
    	      this.displayName = defaults.displayName;
        }

        @CustomType.Setter
        public Builder deployArtifactId(String deployArtifactId) {
            this.deployArtifactId = Objects.requireNonNull(deployArtifactId);
            return this;
        }
        @CustomType.Setter
        public Builder deployPipelineStages(List<GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineArtifactItemDeployPipelineStage> deployPipelineStages) {
            this.deployPipelineStages = Objects.requireNonNull(deployPipelineStages);
            return this;
        }
        public Builder deployPipelineStages(GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineArtifactItemDeployPipelineStage... deployPipelineStages) {
            return deployPipelineStages(List.of(deployPipelineStages));
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineArtifactItem build() {
            final var o = new GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineArtifactItem();
            o.deployArtifactId = deployArtifactId;
            o.deployPipelineStages = deployPipelineStages;
            o.displayName = displayName;
            return o;
        }
    }
}