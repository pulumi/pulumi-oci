// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DevOps.outputs.GetDeployPipelineDeployPipelineParameterItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeployPipelineDeployPipelineParameter {
    /**
     * @return List of parameters defined for a deployment pipeline.
     * 
     */
    private List<GetDeployPipelineDeployPipelineParameterItem> items;

    private GetDeployPipelineDeployPipelineParameter() {}
    /**
     * @return List of parameters defined for a deployment pipeline.
     * 
     */
    public List<GetDeployPipelineDeployPipelineParameterItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployPipelineDeployPipelineParameter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeployPipelineDeployPipelineParameterItem> items;
        public Builder() {}
        public Builder(GetDeployPipelineDeployPipelineParameter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDeployPipelineDeployPipelineParameterItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetDeployPipelineDeployPipelineParameter", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetDeployPipelineDeployPipelineParameterItem... items) {
            return items(List.of(items));
        }
        public GetDeployPipelineDeployPipelineParameter build() {
            final var _resultValue = new GetDeployPipelineDeployPipelineParameter();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
