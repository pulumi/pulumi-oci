// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetWorkRequestErrorsWorkRequestError {
    /**
     * @return A short error code that defines the error, meant for programmatic parsing. See [API Errors](https://docs.cloud.oracle.com/iaas/Content/API/References/apierrors.htm).
     * 
     */
    private String code;
    /**
     * @return A human-readable error string.
     * 
     */
    private String message;
    /**
     * @return The date and time the error occurred.
     * 
     */
    private String timestamp;

    private GetWorkRequestErrorsWorkRequestError() {}
    /**
     * @return A short error code that defines the error, meant for programmatic parsing. See [API Errors](https://docs.cloud.oracle.com/iaas/Content/API/References/apierrors.htm).
     * 
     */
    public String code() {
        return this.code;
    }
    /**
     * @return A human-readable error string.
     * 
     */
    public String message() {
        return this.message;
    }
    /**
     * @return The date and time the error occurred.
     * 
     */
    public String timestamp() {
        return this.timestamp;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkRequestErrorsWorkRequestError defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String code;
        private String message;
        private String timestamp;
        public Builder() {}
        public Builder(GetWorkRequestErrorsWorkRequestError defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.code = defaults.code;
    	      this.message = defaults.message;
    	      this.timestamp = defaults.timestamp;
        }

        @CustomType.Setter
        public Builder code(String code) {
            this.code = Objects.requireNonNull(code);
            return this;
        }
        @CustomType.Setter
        public Builder message(String message) {
            this.message = Objects.requireNonNull(message);
            return this;
        }
        @CustomType.Setter
        public Builder timestamp(String timestamp) {
            this.timestamp = Objects.requireNonNull(timestamp);
            return this;
        }
        public GetWorkRequestErrorsWorkRequestError build() {
            final var o = new GetWorkRequestErrorsWorkRequestError();
            o.code = code;
            o.message = message;
            o.timestamp = timestamp;
            return o;
        }
    }
}