// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStageItem {
    /**
     * @return The OCID of a stage
     * 
     */
    private String deployStageId;
    /**
     * @return Deployment pipeline display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    private String displayName;

    private GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStageItem() {}
    /**
     * @return The OCID of a stage
     * 
     */
    public String deployStageId() {
        return this.deployStageId;
    }
    /**
     * @return Deployment pipeline display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStageItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String deployStageId;
        private String displayName;
        public Builder() {}
        public Builder(GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStageItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.deployStageId = defaults.deployStageId;
    	      this.displayName = defaults.displayName;
        }

        @CustomType.Setter
        public Builder deployStageId(String deployStageId) {
            if (deployStageId == null) {
              throw new MissingRequiredPropertyException("GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStageItem", "deployStageId");
            }
            this.deployStageId = deployStageId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStageItem", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        public GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStageItem build() {
            final var _resultValue = new GetDeployPipelineDeployPipelineArtifactItemDeployPipelineStageItem();
            _resultValue.deployStageId = deployStageId;
            _resultValue.displayName = displayName;
            return _resultValue;
        }
    }
}
