// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetShapeShapeRecommendedAlternative {
    private final String shapeName;

    @CustomType.Constructor
    private GetShapeShapeRecommendedAlternative(@CustomType.Parameter("shapeName") String shapeName) {
        this.shapeName = shapeName;
    }

    public String shapeName() {
        return this.shapeName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetShapeShapeRecommendedAlternative defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String shapeName;

        public Builder() {
    	      // Empty
        }

        public Builder(GetShapeShapeRecommendedAlternative defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.shapeName = defaults.shapeName;
        }

        public Builder shapeName(String shapeName) {
            this.shapeName = Objects.requireNonNull(shapeName);
            return this;
        }        public GetShapeShapeRecommendedAlternative build() {
            return new GetShapeShapeRecommendedAlternative(shapeName);
        }
    }
}
