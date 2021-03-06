// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetCertificatesCertificate {
    /**
     * @return The Certificate Authority certificate, or any interim certificate, that you received from your SSL certificate provider.
     * 
     */
    private final String caCertificate;
    /**
     * @return A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
     * 
     */
    private final String certificateName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the certificate bundles to be listed.
     * 
     */
    private final String loadBalancerId;
    private final @Nullable String passphrase;
    private final String privateKey;
    /**
     * @return The public certificate, in PEM format, that you received from your SSL certificate provider.
     * 
     */
    private final String publicCertificate;
    private final String state;

    @CustomType.Constructor
    private GetCertificatesCertificate(
        @CustomType.Parameter("caCertificate") String caCertificate,
        @CustomType.Parameter("certificateName") String certificateName,
        @CustomType.Parameter("loadBalancerId") String loadBalancerId,
        @CustomType.Parameter("passphrase") @Nullable String passphrase,
        @CustomType.Parameter("privateKey") String privateKey,
        @CustomType.Parameter("publicCertificate") String publicCertificate,
        @CustomType.Parameter("state") String state) {
        this.caCertificate = caCertificate;
        this.certificateName = certificateName;
        this.loadBalancerId = loadBalancerId;
        this.passphrase = passphrase;
        this.privateKey = privateKey;
        this.publicCertificate = publicCertificate;
        this.state = state;
    }

    /**
     * @return The Certificate Authority certificate, or any interim certificate, that you received from your SSL certificate provider.
     * 
     */
    public String caCertificate() {
        return this.caCertificate;
    }
    /**
     * @return A friendly name for the certificate bundle. It must be unique and it cannot be changed. Valid certificate bundle names include only alphanumeric characters, dashes, and underscores. Certificate bundle names cannot contain spaces. Avoid entering confidential information.  Example: `example_certificate_bundle`
     * 
     */
    public String certificateName() {
        return this.certificateName;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the certificate bundles to be listed.
     * 
     */
    public String loadBalancerId() {
        return this.loadBalancerId;
    }
    public Optional<String> passphrase() {
        return Optional.ofNullable(this.passphrase);
    }
    public String privateKey() {
        return this.privateKey;
    }
    /**
     * @return The public certificate, in PEM format, that you received from your SSL certificate provider.
     * 
     */
    public String publicCertificate() {
        return this.publicCertificate;
    }
    public String state() {
        return this.state;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCertificatesCertificate defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String caCertificate;
        private String certificateName;
        private String loadBalancerId;
        private @Nullable String passphrase;
        private String privateKey;
        private String publicCertificate;
        private String state;

        public Builder() {
    	      // Empty
        }

        public Builder(GetCertificatesCertificate defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.caCertificate = defaults.caCertificate;
    	      this.certificateName = defaults.certificateName;
    	      this.loadBalancerId = defaults.loadBalancerId;
    	      this.passphrase = defaults.passphrase;
    	      this.privateKey = defaults.privateKey;
    	      this.publicCertificate = defaults.publicCertificate;
    	      this.state = defaults.state;
        }

        public Builder caCertificate(String caCertificate) {
            this.caCertificate = Objects.requireNonNull(caCertificate);
            return this;
        }
        public Builder certificateName(String certificateName) {
            this.certificateName = Objects.requireNonNull(certificateName);
            return this;
        }
        public Builder loadBalancerId(String loadBalancerId) {
            this.loadBalancerId = Objects.requireNonNull(loadBalancerId);
            return this;
        }
        public Builder passphrase(@Nullable String passphrase) {
            this.passphrase = passphrase;
            return this;
        }
        public Builder privateKey(String privateKey) {
            this.privateKey = Objects.requireNonNull(privateKey);
            return this;
        }
        public Builder publicCertificate(String publicCertificate) {
            this.publicCertificate = Objects.requireNonNull(publicCertificate);
            return this;
        }
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }        public GetCertificatesCertificate build() {
            return new GetCertificatesCertificate(caCertificate, certificateName, loadBalancerId, passphrase, privateKey, publicCertificate, state);
        }
    }
}
