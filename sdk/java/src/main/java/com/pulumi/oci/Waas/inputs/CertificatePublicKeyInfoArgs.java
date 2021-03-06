// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CertificatePublicKeyInfoArgs extends com.pulumi.resources.ResourceArgs {

    public static final CertificatePublicKeyInfoArgs Empty = new CertificatePublicKeyInfoArgs();

    /**
     * The algorithm identifier and parameters for the public key.
     * 
     */
    @Import(name="algorithm")
    private @Nullable Output<String> algorithm;

    /**
     * @return The algorithm identifier and parameters for the public key.
     * 
     */
    public Optional<Output<String>> algorithm() {
        return Optional.ofNullable(this.algorithm);
    }

    /**
     * The private key exponent.
     * 
     */
    @Import(name="exponent")
    private @Nullable Output<Integer> exponent;

    /**
     * @return The private key exponent.
     * 
     */
    public Optional<Output<Integer>> exponent() {
        return Optional.ofNullable(this.exponent);
    }

    /**
     * The number of bits in a key used by a cryptographic algorithm.
     * 
     */
    @Import(name="keySize")
    private @Nullable Output<Integer> keySize;

    /**
     * @return The number of bits in a key used by a cryptographic algorithm.
     * 
     */
    public Optional<Output<Integer>> keySize() {
        return Optional.ofNullable(this.keySize);
    }

    private CertificatePublicKeyInfoArgs() {}

    private CertificatePublicKeyInfoArgs(CertificatePublicKeyInfoArgs $) {
        this.algorithm = $.algorithm;
        this.exponent = $.exponent;
        this.keySize = $.keySize;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CertificatePublicKeyInfoArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CertificatePublicKeyInfoArgs $;

        public Builder() {
            $ = new CertificatePublicKeyInfoArgs();
        }

        public Builder(CertificatePublicKeyInfoArgs defaults) {
            $ = new CertificatePublicKeyInfoArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param algorithm The algorithm identifier and parameters for the public key.
         * 
         * @return builder
         * 
         */
        public Builder algorithm(@Nullable Output<String> algorithm) {
            $.algorithm = algorithm;
            return this;
        }

        /**
         * @param algorithm The algorithm identifier and parameters for the public key.
         * 
         * @return builder
         * 
         */
        public Builder algorithm(String algorithm) {
            return algorithm(Output.of(algorithm));
        }

        /**
         * @param exponent The private key exponent.
         * 
         * @return builder
         * 
         */
        public Builder exponent(@Nullable Output<Integer> exponent) {
            $.exponent = exponent;
            return this;
        }

        /**
         * @param exponent The private key exponent.
         * 
         * @return builder
         * 
         */
        public Builder exponent(Integer exponent) {
            return exponent(Output.of(exponent));
        }

        /**
         * @param keySize The number of bits in a key used by a cryptographic algorithm.
         * 
         * @return builder
         * 
         */
        public Builder keySize(@Nullable Output<Integer> keySize) {
            $.keySize = keySize;
            return this;
        }

        /**
         * @param keySize The number of bits in a key used by a cryptographic algorithm.
         * 
         * @return builder
         * 
         */
        public Builder keySize(Integer keySize) {
            return keySize(Output.of(keySize));
        }

        public CertificatePublicKeyInfoArgs build() {
            return $;
        }
    }

}
