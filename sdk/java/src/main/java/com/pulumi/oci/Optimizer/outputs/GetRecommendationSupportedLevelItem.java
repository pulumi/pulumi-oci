// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetRecommendationSupportedLevelItem {
    /**
     * @return The name of the profile level.
     * 
     */
    private String name;

    private GetRecommendationSupportedLevelItem() {}
    /**
     * @return The name of the profile level.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRecommendationSupportedLevelItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        public Builder() {}
        public Builder(GetRecommendationSupportedLevelItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public GetRecommendationSupportedLevelItem build() {
            final var o = new GetRecommendationSupportedLevelItem();
            o.name = name;
            return o;
        }
    }
}