// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAddonAddonError {
    /**
     * @return A short error code that defines the upstream error, meant for programmatic parsing. See [API Errors](https://docs.cloud.oracle.com/iaas/Content/API/References/apierrors.htm).
     * 
     */
    private String code;
    /**
     * @return A human-readable error string of the upstream error.
     * 
     */
    private String message;
    /**
     * @return The status of the HTTP response encountered in the upstream error.
     * 
     */
    private String status;

    private GetAddonAddonError() {}
    /**
     * @return A short error code that defines the upstream error, meant for programmatic parsing. See [API Errors](https://docs.cloud.oracle.com/iaas/Content/API/References/apierrors.htm).
     * 
     */
    public String code() {
        return this.code;
    }
    /**
     * @return A human-readable error string of the upstream error.
     * 
     */
    public String message() {
        return this.message;
    }
    /**
     * @return The status of the HTTP response encountered in the upstream error.
     * 
     */
    public String status() {
        return this.status;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAddonAddonError defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String code;
        private String message;
        private String status;
        public Builder() {}
        public Builder(GetAddonAddonError defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.code = defaults.code;
    	      this.message = defaults.message;
    	      this.status = defaults.status;
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
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        public GetAddonAddonError build() {
            final var o = new GetAddonAddonError();
            o.code = code;
            o.message = message;
            o.status = status;
            return o;
        }
    }
}