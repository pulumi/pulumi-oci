// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ConnectionLastConnectionValidationResult {
    /**
     * @return A message describing the result of connection validation in more detail.
     * 
     */
    private @Nullable String message;
    /**
     * @return The latest result of whether the credentials pass the validation.
     * 
     */
    private @Nullable String result;
    /**
     * @return The latest timestamp when the connection was validated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    private @Nullable String timeValidated;

    private ConnectionLastConnectionValidationResult() {}
    /**
     * @return A message describing the result of connection validation in more detail.
     * 
     */
    public Optional<String> message() {
        return Optional.ofNullable(this.message);
    }
    /**
     * @return The latest result of whether the credentials pass the validation.
     * 
     */
    public Optional<String> result() {
        return Optional.ofNullable(this.result);
    }
    /**
     * @return The latest timestamp when the connection was validated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    public Optional<String> timeValidated() {
        return Optional.ofNullable(this.timeValidated);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ConnectionLastConnectionValidationResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String message;
        private @Nullable String result;
        private @Nullable String timeValidated;
        public Builder() {}
        public Builder(ConnectionLastConnectionValidationResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.message = defaults.message;
    	      this.result = defaults.result;
    	      this.timeValidated = defaults.timeValidated;
        }

        @CustomType.Setter
        public Builder message(@Nullable String message) {
            this.message = message;
            return this;
        }
        @CustomType.Setter
        public Builder result(@Nullable String result) {
            this.result = result;
            return this;
        }
        @CustomType.Setter
        public Builder timeValidated(@Nullable String timeValidated) {
            this.timeValidated = timeValidated;
            return this;
        }
        public ConnectionLastConnectionValidationResult build() {
            final var o = new ConnectionLastConnectionValidationResult();
            o.message = message;
            o.result = result;
            o.timeValidated = timeValidated;
            return o;
        }
    }
}