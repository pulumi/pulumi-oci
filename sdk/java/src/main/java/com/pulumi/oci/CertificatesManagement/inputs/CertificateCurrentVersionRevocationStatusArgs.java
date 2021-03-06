// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CertificateCurrentVersionRevocationStatusArgs extends com.pulumi.resources.ResourceArgs {

    public static final CertificateCurrentVersionRevocationStatusArgs Empty = new CertificateCurrentVersionRevocationStatusArgs();

    /**
     * The reason the certificate or certificate authority (CA) was revoked.
     * 
     */
    @Import(name="revocationReason")
    private @Nullable Output<String> revocationReason;

    /**
     * @return The reason the certificate or certificate authority (CA) was revoked.
     * 
     */
    public Optional<Output<String>> revocationReason() {
        return Optional.ofNullable(this.revocationReason);
    }

    /**
     * The time when the entity was revoked, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    @Import(name="timeOfRevocation")
    private @Nullable Output<String> timeOfRevocation;

    /**
     * @return The time when the entity was revoked, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeOfRevocation() {
        return Optional.ofNullable(this.timeOfRevocation);
    }

    private CertificateCurrentVersionRevocationStatusArgs() {}

    private CertificateCurrentVersionRevocationStatusArgs(CertificateCurrentVersionRevocationStatusArgs $) {
        this.revocationReason = $.revocationReason;
        this.timeOfRevocation = $.timeOfRevocation;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CertificateCurrentVersionRevocationStatusArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CertificateCurrentVersionRevocationStatusArgs $;

        public Builder() {
            $ = new CertificateCurrentVersionRevocationStatusArgs();
        }

        public Builder(CertificateCurrentVersionRevocationStatusArgs defaults) {
            $ = new CertificateCurrentVersionRevocationStatusArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param revocationReason The reason the certificate or certificate authority (CA) was revoked.
         * 
         * @return builder
         * 
         */
        public Builder revocationReason(@Nullable Output<String> revocationReason) {
            $.revocationReason = revocationReason;
            return this;
        }

        /**
         * @param revocationReason The reason the certificate or certificate authority (CA) was revoked.
         * 
         * @return builder
         * 
         */
        public Builder revocationReason(String revocationReason) {
            return revocationReason(Output.of(revocationReason));
        }

        /**
         * @param timeOfRevocation The time when the entity was revoked, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeOfRevocation(@Nullable Output<String> timeOfRevocation) {
            $.timeOfRevocation = timeOfRevocation;
            return this;
        }

        /**
         * @param timeOfRevocation The time when the entity was revoked, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeOfRevocation(String timeOfRevocation) {
            return timeOfRevocation(Output.of(timeOfRevocation));
        }

        public CertificateCurrentVersionRevocationStatusArgs build() {
            return $;
        }
    }

}
