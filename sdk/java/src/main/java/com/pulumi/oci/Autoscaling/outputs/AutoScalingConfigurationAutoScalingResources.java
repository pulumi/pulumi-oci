// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Autoscaling.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class AutoScalingConfigurationAutoScalingResources {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource that is managed by the autoscaling configuration.
     * 
     */
    private String id;
    /**
     * @return The type of resource.
     * 
     */
    private String type;

    private AutoScalingConfigurationAutoScalingResources() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource that is managed by the autoscaling configuration.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The type of resource.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AutoScalingConfigurationAutoScalingResources defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private String type;
        public Builder() {}
        public Builder(AutoScalingConfigurationAutoScalingResources defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("AutoScalingConfigurationAutoScalingResources", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("AutoScalingConfigurationAutoScalingResources", "type");
            }
            this.type = type;
            return this;
        }
        public AutoScalingConfigurationAutoScalingResources build() {
            final var _resultValue = new AutoScalingConfigurationAutoScalingResources();
            _resultValue.id = id;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
