// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Oda.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class OdaInstanceRestrictedOperation {
    /**
     * @return Name of the restricted operation.
     * 
     */
    private @Nullable String operationName;
    /**
     * @return Name of the service restricting the operation.
     * 
     */
    private @Nullable String restrictingService;

    private OdaInstanceRestrictedOperation() {}
    /**
     * @return Name of the restricted operation.
     * 
     */
    public Optional<String> operationName() {
        return Optional.ofNullable(this.operationName);
    }
    /**
     * @return Name of the service restricting the operation.
     * 
     */
    public Optional<String> restrictingService() {
        return Optional.ofNullable(this.restrictingService);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(OdaInstanceRestrictedOperation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String operationName;
        private @Nullable String restrictingService;
        public Builder() {}
        public Builder(OdaInstanceRestrictedOperation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.operationName = defaults.operationName;
    	      this.restrictingService = defaults.restrictingService;
        }

        @CustomType.Setter
        public Builder operationName(@Nullable String operationName) {
            this.operationName = operationName;
            return this;
        }
        @CustomType.Setter
        public Builder restrictingService(@Nullable String restrictingService) {
            this.restrictingService = restrictingService;
            return this;
        }
        public OdaInstanceRestrictedOperation build() {
            final var o = new OdaInstanceRestrictedOperation();
            o.operationName = operationName;
            o.restrictingService = restrictingService;
            return o;
        }
    }
}