// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CertificateAuthorityCurrentVersionValidityArgs extends com.pulumi.resources.ResourceArgs {

    public static final CertificateAuthorityCurrentVersionValidityArgs Empty = new CertificateAuthorityCurrentVersionValidityArgs();

    /**
     * The date on which the certificate validity period ends, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    @Import(name="timeOfValidityNotAfter")
    private @Nullable Output<String> timeOfValidityNotAfter;

    /**
     * @return The date on which the certificate validity period ends, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeOfValidityNotAfter() {
        return Optional.ofNullable(this.timeOfValidityNotAfter);
    }

    /**
     * The date on which the certificate validity period begins, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    @Import(name="timeOfValidityNotBefore")
    private @Nullable Output<String> timeOfValidityNotBefore;

    /**
     * @return The date on which the certificate validity period begins, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeOfValidityNotBefore() {
        return Optional.ofNullable(this.timeOfValidityNotBefore);
    }

    private CertificateAuthorityCurrentVersionValidityArgs() {}

    private CertificateAuthorityCurrentVersionValidityArgs(CertificateAuthorityCurrentVersionValidityArgs $) {
        this.timeOfValidityNotAfter = $.timeOfValidityNotAfter;
        this.timeOfValidityNotBefore = $.timeOfValidityNotBefore;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CertificateAuthorityCurrentVersionValidityArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CertificateAuthorityCurrentVersionValidityArgs $;

        public Builder() {
            $ = new CertificateAuthorityCurrentVersionValidityArgs();
        }

        public Builder(CertificateAuthorityCurrentVersionValidityArgs defaults) {
            $ = new CertificateAuthorityCurrentVersionValidityArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param timeOfValidityNotAfter The date on which the certificate validity period ends, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeOfValidityNotAfter(@Nullable Output<String> timeOfValidityNotAfter) {
            $.timeOfValidityNotAfter = timeOfValidityNotAfter;
            return this;
        }

        /**
         * @param timeOfValidityNotAfter The date on which the certificate validity period ends, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeOfValidityNotAfter(String timeOfValidityNotAfter) {
            return timeOfValidityNotAfter(Output.of(timeOfValidityNotAfter));
        }

        /**
         * @param timeOfValidityNotBefore The date on which the certificate validity period begins, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeOfValidityNotBefore(@Nullable Output<String> timeOfValidityNotBefore) {
            $.timeOfValidityNotBefore = timeOfValidityNotBefore;
            return this;
        }

        /**
         * @param timeOfValidityNotBefore The date on which the certificate validity period begins, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeOfValidityNotBefore(String timeOfValidityNotBefore) {
            return timeOfValidityNotBefore(Output.of(timeOfValidityNotBefore));
        }

        public CertificateAuthorityCurrentVersionValidityArgs build() {
            return $;
        }
    }

}
