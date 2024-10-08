// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DevOps.outputs.GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStageItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStage {
    /**
     * @return List of parameters defined for a deployment pipeline.
     * 
     */
    private List<GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStageItem> items;

    private GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStage() {}
    /**
     * @return List of parameters defined for a deployment pipeline.
     * 
     */
    public List<GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStageItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStage defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStageItem> items;
        public Builder() {}
        public Builder(GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStage defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStageItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStage", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStageItem... items) {
            return items(List.of(items));
        }
        public GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStage build() {
            final var _resultValue = new GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStage();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
