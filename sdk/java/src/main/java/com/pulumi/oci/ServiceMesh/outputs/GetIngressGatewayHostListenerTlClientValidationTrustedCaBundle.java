// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetIngressGatewayHostListenerTlClientValidationTrustedCaBundle {
    /**
     * @return The OCID of the CA Bundle resource.
     * 
     */
    private String caBundleId;
    /**
     * @return Name of the secret. For Kubernetes this is the name of the Kubernetes secret of type tls. For other platforms the secrets must be mounted at: /etc/oci/secrets/${secretName}/tls.{key,crt}
     * 
     */
    private String secretName;
    /**
     * @return Type of certificate.
     * 
     */
    private String type;

    private GetIngressGatewayHostListenerTlClientValidationTrustedCaBundle() {}
    /**
     * @return The OCID of the CA Bundle resource.
     * 
     */
    public String caBundleId() {
        return this.caBundleId;
    }
    /**
     * @return Name of the secret. For Kubernetes this is the name of the Kubernetes secret of type tls. For other platforms the secrets must be mounted at: /etc/oci/secrets/${secretName}/tls.{key,crt}
     * 
     */
    public String secretName() {
        return this.secretName;
    }
    /**
     * @return Type of certificate.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIngressGatewayHostListenerTlClientValidationTrustedCaBundle defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String caBundleId;
        private String secretName;
        private String type;
        public Builder() {}
        public Builder(GetIngressGatewayHostListenerTlClientValidationTrustedCaBundle defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.caBundleId = defaults.caBundleId;
    	      this.secretName = defaults.secretName;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder caBundleId(String caBundleId) {
            this.caBundleId = Objects.requireNonNull(caBundleId);
            return this;
        }
        @CustomType.Setter
        public Builder secretName(String secretName) {
            this.secretName = Objects.requireNonNull(secretName);
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public GetIngressGatewayHostListenerTlClientValidationTrustedCaBundle build() {
            final var o = new GetIngressGatewayHostListenerTlClientValidationTrustedCaBundle();
            o.caBundleId = caBundleId;
            o.secretName = secretName;
            o.type = type;
            return o;
        }
    }
}