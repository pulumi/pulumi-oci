// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsAppsAppCertificate {
    /**
     * @return Certificate alias
     * 
     */
    private String certAlias;
    /**
     * @return Certificate kid
     * 
     */
    private String kid;
    /**
     * @return sha1Thumbprint
     * 
     */
    private String sha1thumbprint;
    /**
     * @return Base-64-encoded certificate.
     * 
     */
    private String x509base64certificate;
    /**
     * @return Certificate x5t
     * 
     */
    private String x5t;

    private GetDomainsAppsAppCertificate() {}
    /**
     * @return Certificate alias
     * 
     */
    public String certAlias() {
        return this.certAlias;
    }
    /**
     * @return Certificate kid
     * 
     */
    public String kid() {
        return this.kid;
    }
    /**
     * @return sha1Thumbprint
     * 
     */
    public String sha1thumbprint() {
        return this.sha1thumbprint;
    }
    /**
     * @return Base-64-encoded certificate.
     * 
     */
    public String x509base64certificate() {
        return this.x509base64certificate;
    }
    /**
     * @return Certificate x5t
     * 
     */
    public String x5t() {
        return this.x5t;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAppsAppCertificate defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String certAlias;
        private String kid;
        private String sha1thumbprint;
        private String x509base64certificate;
        private String x5t;
        public Builder() {}
        public Builder(GetDomainsAppsAppCertificate defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.certAlias = defaults.certAlias;
    	      this.kid = defaults.kid;
    	      this.sha1thumbprint = defaults.sha1thumbprint;
    	      this.x509base64certificate = defaults.x509base64certificate;
    	      this.x5t = defaults.x5t;
        }

        @CustomType.Setter
        public Builder certAlias(String certAlias) {
            this.certAlias = Objects.requireNonNull(certAlias);
            return this;
        }
        @CustomType.Setter
        public Builder kid(String kid) {
            this.kid = Objects.requireNonNull(kid);
            return this;
        }
        @CustomType.Setter
        public Builder sha1thumbprint(String sha1thumbprint) {
            this.sha1thumbprint = Objects.requireNonNull(sha1thumbprint);
            return this;
        }
        @CustomType.Setter
        public Builder x509base64certificate(String x509base64certificate) {
            this.x509base64certificate = Objects.requireNonNull(x509base64certificate);
            return this;
        }
        @CustomType.Setter
        public Builder x5t(String x5t) {
            this.x5t = Objects.requireNonNull(x5t);
            return this;
        }
        public GetDomainsAppsAppCertificate build() {
            final var o = new GetDomainsAppsAppCertificate();
            o.certAlias = certAlias;
            o.kid = kid;
            o.sha1thumbprint = sha1thumbprint;
            o.x509base64certificate = x509base64certificate;
            o.x5t = x5t;
            return o;
        }
    }
}