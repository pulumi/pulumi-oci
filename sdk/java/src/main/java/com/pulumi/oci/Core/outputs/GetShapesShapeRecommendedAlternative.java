// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetShapesShapeRecommendedAlternative {
    /**
     * @return The name of the shape.
     * 
     */
    private String shapeName;

    private GetShapesShapeRecommendedAlternative() {}
    /**
     * @return The name of the shape.
     * 
     */
    public String shapeName() {
        return this.shapeName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetShapesShapeRecommendedAlternative defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String shapeName;
        public Builder() {}
        public Builder(GetShapesShapeRecommendedAlternative defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.shapeName = defaults.shapeName;
        }

        @CustomType.Setter
        public Builder shapeName(String shapeName) {
            this.shapeName = Objects.requireNonNull(shapeName);
            return this;
        }
        public GetShapesShapeRecommendedAlternative build() {
            final var o = new GetShapesShapeRecommendedAlternative();
            o.shapeName = shapeName;
            return o;
        }
    }
}