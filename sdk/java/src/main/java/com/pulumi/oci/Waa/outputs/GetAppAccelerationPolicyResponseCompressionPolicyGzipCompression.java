// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waa.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.util.Objects;

@CustomType
public final class GetAppAccelerationPolicyResponseCompressionPolicyGzipCompression {
    /**
     * @return When true, support for gzip compression is enabled. HTTP responses will be compressed with gzip only if the client indicates support for gzip via the &#34;Accept-Encoding: gzip&#34; request header.
     * 
     */
    private Boolean isEnabled;

    private GetAppAccelerationPolicyResponseCompressionPolicyGzipCompression() {}
    /**
     * @return When true, support for gzip compression is enabled. HTTP responses will be compressed with gzip only if the client indicates support for gzip via the &#34;Accept-Encoding: gzip&#34; request header.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAppAccelerationPolicyResponseCompressionPolicyGzipCompression defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean isEnabled;
        public Builder() {}
        public Builder(GetAppAccelerationPolicyResponseCompressionPolicyGzipCompression defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isEnabled = defaults.isEnabled;
        }

        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            if (isEnabled == null) {
              throw new MissingRequiredPropertyException("GetAppAccelerationPolicyResponseCompressionPolicyGzipCompression", "isEnabled");
            }
            this.isEnabled = isEnabled;
            return this;
        }
        public GetAppAccelerationPolicyResponseCompressionPolicyGzipCompression build() {
            final var _resultValue = new GetAppAccelerationPolicyResponseCompressionPolicyGzipCompression();
            _resultValue.isEnabled = isEnabled;
            return _resultValue;
        }
    }
}
