// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.BigDataService.outputs.GetBdsInstanceStartClusterShapeConfigNodeTypeShapeConfig;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetBdsInstanceStartClusterShapeConfig {
    private List<GetBdsInstanceStartClusterShapeConfigNodeTypeShapeConfig> nodeTypeShapeConfigs;

    private GetBdsInstanceStartClusterShapeConfig() {}
    public List<GetBdsInstanceStartClusterShapeConfigNodeTypeShapeConfig> nodeTypeShapeConfigs() {
        return this.nodeTypeShapeConfigs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBdsInstanceStartClusterShapeConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetBdsInstanceStartClusterShapeConfigNodeTypeShapeConfig> nodeTypeShapeConfigs;
        public Builder() {}
        public Builder(GetBdsInstanceStartClusterShapeConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.nodeTypeShapeConfigs = defaults.nodeTypeShapeConfigs;
        }

        @CustomType.Setter
        public Builder nodeTypeShapeConfigs(List<GetBdsInstanceStartClusterShapeConfigNodeTypeShapeConfig> nodeTypeShapeConfigs) {
            if (nodeTypeShapeConfigs == null) {
              throw new MissingRequiredPropertyException("GetBdsInstanceStartClusterShapeConfig", "nodeTypeShapeConfigs");
            }
            this.nodeTypeShapeConfigs = nodeTypeShapeConfigs;
            return this;
        }
        public Builder nodeTypeShapeConfigs(GetBdsInstanceStartClusterShapeConfigNodeTypeShapeConfig... nodeTypeShapeConfigs) {
            return nodeTypeShapeConfigs(List.of(nodeTypeShapeConfigs));
        }
        public GetBdsInstanceStartClusterShapeConfig build() {
            final var _resultValue = new GetBdsInstanceStartClusterShapeConfig();
            _resultValue.nodeTypeShapeConfigs = nodeTypeShapeConfigs;
            return _resultValue;
        }
    }
}
