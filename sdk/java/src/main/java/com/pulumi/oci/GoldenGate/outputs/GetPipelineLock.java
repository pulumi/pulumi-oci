// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetPipelineLock {
    /**
     * @return A message added by the creator of the lock. This is typically used to give an indication of why the resource is locked.
     * 
     */
    private String message;
    /**
     * @return Type of the lock.
     * 
     */
    private String type;

    private GetPipelineLock() {}
    /**
     * @return A message added by the creator of the lock. This is typically used to give an indication of why the resource is locked.
     * 
     */
    public String message() {
        return this.message;
    }
    /**
     * @return Type of the lock.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPipelineLock defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String message;
        private String type;
        public Builder() {}
        public Builder(GetPipelineLock defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.message = defaults.message;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder message(String message) {
            if (message == null) {
              throw new MissingRequiredPropertyException("GetPipelineLock", "message");
            }
            this.message = message;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetPipelineLock", "type");
            }
            this.type = type;
            return this;
        }
        public GetPipelineLock build() {
            final var _resultValue = new GetPipelineLock();
            _resultValue.message = message;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
