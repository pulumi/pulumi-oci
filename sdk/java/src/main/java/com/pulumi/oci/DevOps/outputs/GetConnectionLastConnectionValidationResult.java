// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetConnectionLastConnectionValidationResult {
    /**
     * @return A message describing the result of connection validation in more detail.
     * 
     */
    private String message;
    /**
     * @return The latest result of whether the credentials pass the validation.
     * 
     */
    private String result;
    /**
     * @return The latest timestamp when the connection was validated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    private String timeValidated;

    private GetConnectionLastConnectionValidationResult() {}
    /**
     * @return A message describing the result of connection validation in more detail.
     * 
     */
    public String message() {
        return this.message;
    }
    /**
     * @return The latest result of whether the credentials pass the validation.
     * 
     */
    public String result() {
        return this.result;
    }
    /**
     * @return The latest timestamp when the connection was validated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
     * 
     */
    public String timeValidated() {
        return this.timeValidated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetConnectionLastConnectionValidationResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String message;
        private String result;
        private String timeValidated;
        public Builder() {}
        public Builder(GetConnectionLastConnectionValidationResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.message = defaults.message;
    	      this.result = defaults.result;
    	      this.timeValidated = defaults.timeValidated;
        }

        @CustomType.Setter
        public Builder message(String message) {
            if (message == null) {
              throw new MissingRequiredPropertyException("GetConnectionLastConnectionValidationResult", "message");
            }
            this.message = message;
            return this;
        }
        @CustomType.Setter
        public Builder result(String result) {
            if (result == null) {
              throw new MissingRequiredPropertyException("GetConnectionLastConnectionValidationResult", "result");
            }
            this.result = result;
            return this;
        }
        @CustomType.Setter
        public Builder timeValidated(String timeValidated) {
            if (timeValidated == null) {
              throw new MissingRequiredPropertyException("GetConnectionLastConnectionValidationResult", "timeValidated");
            }
            this.timeValidated = timeValidated;
            return this;
        }
        public GetConnectionLastConnectionValidationResult build() {
            final var _resultValue = new GetConnectionLastConnectionValidationResult();
            _resultValue.message = message;
            _resultValue.result = result;
            _resultValue.timeValidated = timeValidated;
            return _resultValue;
        }
    }
}
