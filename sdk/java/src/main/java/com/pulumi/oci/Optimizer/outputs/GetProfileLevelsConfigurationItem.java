// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetProfileLevelsConfigurationItem {
    /**
     * @return The pre-defined profile level.
     * 
     */
    private String level;
    /**
     * @return The unique OCID of the recommendation.
     * 
     */
    private String recommendationId;

    private GetProfileLevelsConfigurationItem() {}
    /**
     * @return The pre-defined profile level.
     * 
     */
    public String level() {
        return this.level;
    }
    /**
     * @return The unique OCID of the recommendation.
     * 
     */
    public String recommendationId() {
        return this.recommendationId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetProfileLevelsConfigurationItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String level;
        private String recommendationId;
        public Builder() {}
        public Builder(GetProfileLevelsConfigurationItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.level = defaults.level;
    	      this.recommendationId = defaults.recommendationId;
        }

        @CustomType.Setter
        public Builder level(String level) {
            this.level = Objects.requireNonNull(level);
            return this;
        }
        @CustomType.Setter
        public Builder recommendationId(String recommendationId) {
            this.recommendationId = Objects.requireNonNull(recommendationId);
            return this;
        }
        public GetProfileLevelsConfigurationItem build() {
            final var o = new GetProfileLevelsConfigurationItem();
            o.level = level;
            o.recommendationId = recommendationId;
            return o;
        }
    }
}