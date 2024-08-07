// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerInstances.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Double;
import java.util.Objects;

@CustomType
public final class GetContainerInstanceContainerResourceConfig {
    private Double memoryLimitInGbs;
    private Double vcpusLimit;

    private GetContainerInstanceContainerResourceConfig() {}
    public Double memoryLimitInGbs() {
        return this.memoryLimitInGbs;
    }
    public Double vcpusLimit() {
        return this.vcpusLimit;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetContainerInstanceContainerResourceConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Double memoryLimitInGbs;
        private Double vcpusLimit;
        public Builder() {}
        public Builder(GetContainerInstanceContainerResourceConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.memoryLimitInGbs = defaults.memoryLimitInGbs;
    	      this.vcpusLimit = defaults.vcpusLimit;
        }

        @CustomType.Setter
        public Builder memoryLimitInGbs(Double memoryLimitInGbs) {
            if (memoryLimitInGbs == null) {
              throw new MissingRequiredPropertyException("GetContainerInstanceContainerResourceConfig", "memoryLimitInGbs");
            }
            this.memoryLimitInGbs = memoryLimitInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder vcpusLimit(Double vcpusLimit) {
            if (vcpusLimit == null) {
              throw new MissingRequiredPropertyException("GetContainerInstanceContainerResourceConfig", "vcpusLimit");
            }
            this.vcpusLimit = vcpusLimit;
            return this;
        }
        public GetContainerInstanceContainerResourceConfig build() {
            final var _resultValue = new GetContainerInstanceContainerResourceConfig();
            _resultValue.memoryLimitInGbs = memoryLimitInGbs;
            _resultValue.vcpusLimit = vcpusLimit;
            return _resultValue;
        }
    }
}
