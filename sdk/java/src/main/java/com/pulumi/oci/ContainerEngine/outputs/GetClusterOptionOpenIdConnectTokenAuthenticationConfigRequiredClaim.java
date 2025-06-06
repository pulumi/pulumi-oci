// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetClusterOptionOpenIdConnectTokenAuthenticationConfigRequiredClaim {
    /**
     * @return The key of the pair.
     * 
     */
    private String key;
    /**
     * @return The value of the pair.
     * 
     */
    private String value;

    private GetClusterOptionOpenIdConnectTokenAuthenticationConfigRequiredClaim() {}
    /**
     * @return The key of the pair.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return The value of the pair.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetClusterOptionOpenIdConnectTokenAuthenticationConfigRequiredClaim defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String key;
        private String value;
        public Builder() {}
        public Builder(GetClusterOptionOpenIdConnectTokenAuthenticationConfigRequiredClaim defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.key = defaults.key;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetClusterOptionOpenIdConnectTokenAuthenticationConfigRequiredClaim", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetClusterOptionOpenIdConnectTokenAuthenticationConfigRequiredClaim", "value");
            }
            this.value = value;
            return this;
        }
        public GetClusterOptionOpenIdConnectTokenAuthenticationConfigRequiredClaim build() {
            final var _resultValue = new GetClusterOptionOpenIdConnectTokenAuthenticationConfigRequiredClaim();
            _resultValue.key = key;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
