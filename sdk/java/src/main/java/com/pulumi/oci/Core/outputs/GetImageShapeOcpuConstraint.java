// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class GetImageShapeOcpuConstraint {
    /**
     * @return The maximum number of OCPUs supported for this image and shape.
     * 
     */
    private Integer max;
    /**
     * @return The minimum number of OCPUs supported for this image and shape.
     * 
     */
    private Integer min;

    private GetImageShapeOcpuConstraint() {}
    /**
     * @return The maximum number of OCPUs supported for this image and shape.
     * 
     */
    public Integer max() {
        return this.max;
    }
    /**
     * @return The minimum number of OCPUs supported for this image and shape.
     * 
     */
    public Integer min() {
        return this.min;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetImageShapeOcpuConstraint defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer max;
        private Integer min;
        public Builder() {}
        public Builder(GetImageShapeOcpuConstraint defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.max = defaults.max;
    	      this.min = defaults.min;
        }

        @CustomType.Setter
        public Builder max(Integer max) {
            this.max = Objects.requireNonNull(max);
            return this;
        }
        @CustomType.Setter
        public Builder min(Integer min) {
            this.min = Objects.requireNonNull(min);
            return this;
        }
        public GetImageShapeOcpuConstraint build() {
            final var o = new GetImageShapeOcpuConstraint();
            o.max = max;
            o.min = min;
            return o;
        }
    }
}