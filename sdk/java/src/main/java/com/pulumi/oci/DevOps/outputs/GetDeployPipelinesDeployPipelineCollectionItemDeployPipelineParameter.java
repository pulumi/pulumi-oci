// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineParameterItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineParameter {
    /**
     * @return List of parameters defined for a deployment pipeline.
     * 
     */
    private final List<GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineParameterItem> items;

    @CustomType.Constructor
    private GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineParameter(@CustomType.Parameter("items") List<GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineParameterItem> items) {
        this.items = items;
    }

    /**
     * @return List of parameters defined for a deployment pipeline.
     * 
     */
    public List<GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineParameterItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineParameter defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineParameterItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineParameter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineParameterItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineParameterItem... items) {
            return items(List.of(items));
        }        public GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineParameter build() {
            return new GetDeployPipelinesDeployPipelineCollectionItemDeployPipelineParameter(items);
        }
    }
}
