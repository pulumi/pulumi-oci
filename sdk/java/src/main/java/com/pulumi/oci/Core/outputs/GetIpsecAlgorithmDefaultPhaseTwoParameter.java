// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetIpsecAlgorithmDefaultPhaseTwoParameter {
    /**
     * @return Default phase two authentication algorithms.
     * 
     */
    private List<String> defaultAuthenticationAlgorithms;
    /**
     * @return Default phase two encryption algorithms.
     * 
     */
    private List<String> defaultEncryptionAlgorithms;
    /**
     * @return Default perfect forward secrecy Diffie-Hellman groups.
     * 
     */
    private String defaultPfsDhGroup;

    private GetIpsecAlgorithmDefaultPhaseTwoParameter() {}
    /**
     * @return Default phase two authentication algorithms.
     * 
     */
    public List<String> defaultAuthenticationAlgorithms() {
        return this.defaultAuthenticationAlgorithms;
    }
    /**
     * @return Default phase two encryption algorithms.
     * 
     */
    public List<String> defaultEncryptionAlgorithms() {
        return this.defaultEncryptionAlgorithms;
    }
    /**
     * @return Default perfect forward secrecy Diffie-Hellman groups.
     * 
     */
    public String defaultPfsDhGroup() {
        return this.defaultPfsDhGroup;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIpsecAlgorithmDefaultPhaseTwoParameter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> defaultAuthenticationAlgorithms;
        private List<String> defaultEncryptionAlgorithms;
        private String defaultPfsDhGroup;
        public Builder() {}
        public Builder(GetIpsecAlgorithmDefaultPhaseTwoParameter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.defaultAuthenticationAlgorithms = defaults.defaultAuthenticationAlgorithms;
    	      this.defaultEncryptionAlgorithms = defaults.defaultEncryptionAlgorithms;
    	      this.defaultPfsDhGroup = defaults.defaultPfsDhGroup;
        }

        @CustomType.Setter
        public Builder defaultAuthenticationAlgorithms(List<String> defaultAuthenticationAlgorithms) {
            if (defaultAuthenticationAlgorithms == null) {
              throw new MissingRequiredPropertyException("GetIpsecAlgorithmDefaultPhaseTwoParameter", "defaultAuthenticationAlgorithms");
            }
            this.defaultAuthenticationAlgorithms = defaultAuthenticationAlgorithms;
            return this;
        }
        public Builder defaultAuthenticationAlgorithms(String... defaultAuthenticationAlgorithms) {
            return defaultAuthenticationAlgorithms(List.of(defaultAuthenticationAlgorithms));
        }
        @CustomType.Setter
        public Builder defaultEncryptionAlgorithms(List<String> defaultEncryptionAlgorithms) {
            if (defaultEncryptionAlgorithms == null) {
              throw new MissingRequiredPropertyException("GetIpsecAlgorithmDefaultPhaseTwoParameter", "defaultEncryptionAlgorithms");
            }
            this.defaultEncryptionAlgorithms = defaultEncryptionAlgorithms;
            return this;
        }
        public Builder defaultEncryptionAlgorithms(String... defaultEncryptionAlgorithms) {
            return defaultEncryptionAlgorithms(List.of(defaultEncryptionAlgorithms));
        }
        @CustomType.Setter
        public Builder defaultPfsDhGroup(String defaultPfsDhGroup) {
            if (defaultPfsDhGroup == null) {
              throw new MissingRequiredPropertyException("GetIpsecAlgorithmDefaultPhaseTwoParameter", "defaultPfsDhGroup");
            }
            this.defaultPfsDhGroup = defaultPfsDhGroup;
            return this;
        }
        public GetIpsecAlgorithmDefaultPhaseTwoParameter build() {
            final var _resultValue = new GetIpsecAlgorithmDefaultPhaseTwoParameter();
            _resultValue.defaultAuthenticationAlgorithms = defaultAuthenticationAlgorithms;
            _resultValue.defaultEncryptionAlgorithms = defaultEncryptionAlgorithms;
            _resultValue.defaultPfsDhGroup = defaultPfsDhGroup;
            return _resultValue;
        }
    }
}
