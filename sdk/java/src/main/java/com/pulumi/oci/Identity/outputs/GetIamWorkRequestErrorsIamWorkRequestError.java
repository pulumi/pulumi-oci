// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetIamWorkRequestErrorsIamWorkRequestError {
    /**
     * @return A machine-usable code for the error that occured.
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

    private GetIamWorkRequestErrorsIamWorkRequestError() {}
    /**
     * @return A machine-usable code for the error that occured.
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

    public static Builder builder(GetIamWorkRequestErrorsIamWorkRequestError defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String code;
        private String message;
        private String timestamp;
        public Builder() {}
        public Builder(GetIamWorkRequestErrorsIamWorkRequestError defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.code = defaults.code;
    	      this.message = defaults.message;
    	      this.timestamp = defaults.timestamp;
        }

        @CustomType.Setter
        public Builder code(String code) {
            if (code == null) {
              throw new MissingRequiredPropertyException("GetIamWorkRequestErrorsIamWorkRequestError", "code");
            }
            this.code = code;
            return this;
        }
        @CustomType.Setter
        public Builder message(String message) {
            if (message == null) {
              throw new MissingRequiredPropertyException("GetIamWorkRequestErrorsIamWorkRequestError", "message");
            }
            this.message = message;
            return this;
        }
        @CustomType.Setter
        public Builder timestamp(String timestamp) {
            if (timestamp == null) {
              throw new MissingRequiredPropertyException("GetIamWorkRequestErrorsIamWorkRequestError", "timestamp");
            }
            this.timestamp = timestamp;
            return this;
        }
        public GetIamWorkRequestErrorsIamWorkRequestError build() {
            final var _resultValue = new GetIamWorkRequestErrorsIamWorkRequestError();
            _resultValue.code = code;
            _resultValue.message = message;
            _resultValue.timestamp = timestamp;
            return _resultValue;
        }
    }
}
