// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDeploymentDeploymentArgumentItem {
    /**
     * @return Name of the step.
     * 
     */
    private final String name;
    /**
     * @return value of the argument.
     * 
     */
    private final String value;

    @CustomType.Constructor
    private GetDeploymentDeploymentArgumentItem(
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("value") String value) {
        this.name = name;
        this.value = value;
    }

    /**
     * @return Name of the step.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return value of the argument.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentDeploymentArgumentItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String name;
        private String value;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDeploymentDeploymentArgumentItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.value = defaults.value;
        }

        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }        public GetDeploymentDeploymentArgumentItem build() {
            return new GetDeploymentDeploymentArgumentItem(name, value);
        }
    }
}
