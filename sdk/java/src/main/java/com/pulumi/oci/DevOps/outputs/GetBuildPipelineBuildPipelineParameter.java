// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetBuildPipelineBuildPipelineParameterItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetBuildPipelineBuildPipelineParameter {
    /**
     * @return List of parameters defined for a build pipeline.
     * 
     */
    private final List<GetBuildPipelineBuildPipelineParameterItem> items;

    @CustomType.Constructor
    private GetBuildPipelineBuildPipelineParameter(@CustomType.Parameter("items") List<GetBuildPipelineBuildPipelineParameterItem> items) {
        this.items = items;
    }

    /**
     * @return List of parameters defined for a build pipeline.
     * 
     */
    public List<GetBuildPipelineBuildPipelineParameterItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBuildPipelineBuildPipelineParameter defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetBuildPipelineBuildPipelineParameterItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetBuildPipelineBuildPipelineParameter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetBuildPipelineBuildPipelineParameterItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetBuildPipelineBuildPipelineParameterItem... items) {
            return items(List.of(items));
        }        public GetBuildPipelineBuildPipelineParameter build() {
            return new GetBuildPipelineBuildPipelineParameter(items);
        }
    }
}
