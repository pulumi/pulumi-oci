// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetKeysKeyKeyShape {
    /**
     * @return The algorithm used by a key&#39;s key versions to encrypt or decrypt data. Currently, support includes AES, RSA, and ECDSA algorithms.
     * 
     */
    private final String algorithm;
    /**
     * @return The curve ID of the keys. (This pertains only to ECDSA keys.)
     * 
     */
    private final String curveId;
    /**
     * @return The length of the key in bytes, expressed as an integer. Supported values include 16, 24, or 32.
     * 
     */
    private final Integer length;

    @CustomType.Constructor
    private GetKeysKeyKeyShape(
        @CustomType.Parameter("algorithm") String algorithm,
        @CustomType.Parameter("curveId") String curveId,
        @CustomType.Parameter("length") Integer length) {
        this.algorithm = algorithm;
        this.curveId = curveId;
        this.length = length;
    }

    /**
     * @return The algorithm used by a key&#39;s key versions to encrypt or decrypt data. Currently, support includes AES, RSA, and ECDSA algorithms.
     * 
     */
    public String algorithm() {
        return this.algorithm;
    }
    /**
     * @return The curve ID of the keys. (This pertains only to ECDSA keys.)
     * 
     */
    public String curveId() {
        return this.curveId;
    }
    /**
     * @return The length of the key in bytes, expressed as an integer. Supported values include 16, 24, or 32.
     * 
     */
    public Integer length() {
        return this.length;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetKeysKeyKeyShape defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String algorithm;
        private String curveId;
        private Integer length;

        public Builder() {
    	      // Empty
        }

        public Builder(GetKeysKeyKeyShape defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.algorithm = defaults.algorithm;
    	      this.curveId = defaults.curveId;
    	      this.length = defaults.length;
        }

        public Builder algorithm(String algorithm) {
            this.algorithm = Objects.requireNonNull(algorithm);
            return this;
        }
        public Builder curveId(String curveId) {
            this.curveId = Objects.requireNonNull(curveId);
            return this;
        }
        public Builder length(Integer length) {
            this.length = Objects.requireNonNull(length);
            return this;
        }        public GetKeysKeyKeyShape build() {
            return new GetKeysKeyKeyShape(algorithm, curveId, length);
        }
    }
}
