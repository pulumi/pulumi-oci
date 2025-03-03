// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class BdsInstanceStartClusterShapeConfigNodeTypeShapeConfig {
    /**
     * @return BDS instance node type
     * 
     */
    private @Nullable String nodeType;
    /**
     * @return Shape of the node
     * 
     */
    private @Nullable String shape;

    private BdsInstanceStartClusterShapeConfigNodeTypeShapeConfig() {}
    /**
     * @return BDS instance node type
     * 
     */
    public Optional<String> nodeType() {
        return Optional.ofNullable(this.nodeType);
    }
    /**
     * @return Shape of the node
     * 
     */
    public Optional<String> shape() {
        return Optional.ofNullable(this.shape);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(BdsInstanceStartClusterShapeConfigNodeTypeShapeConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String nodeType;
        private @Nullable String shape;
        public Builder() {}
        public Builder(BdsInstanceStartClusterShapeConfigNodeTypeShapeConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.nodeType = defaults.nodeType;
    	      this.shape = defaults.shape;
        }

        @CustomType.Setter
        public Builder nodeType(@Nullable String nodeType) {

            this.nodeType = nodeType;
            return this;
        }
        @CustomType.Setter
        public Builder shape(@Nullable String shape) {

            this.shape = shape;
            return this;
        }
        public BdsInstanceStartClusterShapeConfigNodeTypeShapeConfig build() {
            final var _resultValue = new BdsInstanceStartClusterShapeConfigNodeTypeShapeConfig();
            _resultValue.nodeType = nodeType;
            _resultValue.shape = shape;
            return _resultValue;
        }
    }
}
