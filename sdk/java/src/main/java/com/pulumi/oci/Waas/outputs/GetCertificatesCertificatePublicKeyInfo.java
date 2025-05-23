// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetCertificatesCertificatePublicKeyInfo {
    /**
     * @return The algorithm identifier and parameters for the public key.
     * 
     */
    private String algorithm;
    /**
     * @return The private key exponent.
     * 
     */
    private Integer exponent;
    /**
     * @return The number of bits in a key used by a cryptographic algorithm.
     * 
     */
    private Integer keySize;

    private GetCertificatesCertificatePublicKeyInfo() {}
    /**
     * @return The algorithm identifier and parameters for the public key.
     * 
     */
    public String algorithm() {
        return this.algorithm;
    }
    /**
     * @return The private key exponent.
     * 
     */
    public Integer exponent() {
        return this.exponent;
    }
    /**
     * @return The number of bits in a key used by a cryptographic algorithm.
     * 
     */
    public Integer keySize() {
        return this.keySize;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCertificatesCertificatePublicKeyInfo defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String algorithm;
        private Integer exponent;
        private Integer keySize;
        public Builder() {}
        public Builder(GetCertificatesCertificatePublicKeyInfo defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.algorithm = defaults.algorithm;
    	      this.exponent = defaults.exponent;
    	      this.keySize = defaults.keySize;
        }

        @CustomType.Setter
        public Builder algorithm(String algorithm) {
            if (algorithm == null) {
              throw new MissingRequiredPropertyException("GetCertificatesCertificatePublicKeyInfo", "algorithm");
            }
            this.algorithm = algorithm;
            return this;
        }
        @CustomType.Setter
        public Builder exponent(Integer exponent) {
            if (exponent == null) {
              throw new MissingRequiredPropertyException("GetCertificatesCertificatePublicKeyInfo", "exponent");
            }
            this.exponent = exponent;
            return this;
        }
        @CustomType.Setter
        public Builder keySize(Integer keySize) {
            if (keySize == null) {
              throw new MissingRequiredPropertyException("GetCertificatesCertificatePublicKeyInfo", "keySize");
            }
            this.keySize = keySize;
            return this;
        }
        public GetCertificatesCertificatePublicKeyInfo build() {
            final var _resultValue = new GetCertificatesCertificatePublicKeyInfo();
            _resultValue.algorithm = algorithm;
            _resultValue.exponent = exponent;
            _resultValue.keySize = keySize;
            return _resultValue;
        }
    }
}
