// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Autoscaling.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAutoScalingConfigurationsAutoScalingConfigurationAutoScalingResource {
    /**
     * @return ID of the condition that is assigned after creation.
     * 
     */
    private String id;
    /**
     * @return The type of action to take.
     * 
     */
    private String type;

    private GetAutoScalingConfigurationsAutoScalingConfigurationAutoScalingResource() {}
    /**
     * @return ID of the condition that is assigned after creation.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The type of action to take.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutoScalingConfigurationsAutoScalingConfigurationAutoScalingResource defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private String type;
        public Builder() {}
        public Builder(GetAutoScalingConfigurationsAutoScalingConfigurationAutoScalingResource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetAutoScalingConfigurationsAutoScalingConfigurationAutoScalingResource build() {
            final var o = new GetAutoScalingConfigurationsAutoScalingConfigurationAutoScalingResource();
            o.id = id;
            o.type = type;
            return o;
        }
    }
}