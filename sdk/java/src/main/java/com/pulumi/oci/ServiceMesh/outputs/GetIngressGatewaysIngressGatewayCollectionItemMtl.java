// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetIngressGatewaysIngressGatewayCollectionItemMtl {
    /**
     * @return The OCID of the certificate resource that will be used for mTLS authentication with other virtual services in the mesh.
     * 
     */
    private String certificateId;
    /**
     * @return The number of days the mTLS certificate is valid.  This value should be less than the Maximum Validity Duration  for Certificates (Days) setting on the Certificate Authority associated with this Mesh.  The certificate will be automatically renewed after 2/3 of the validity period, so a certificate with a maximum validity of 45 days will be renewed every 30 days.
     * 
     */
    private Integer maximumValidity;

    private GetIngressGatewaysIngressGatewayCollectionItemMtl() {}
    /**
     * @return The OCID of the certificate resource that will be used for mTLS authentication with other virtual services in the mesh.
     * 
     */
    public String certificateId() {
        return this.certificateId;
    }
    /**
     * @return The number of days the mTLS certificate is valid.  This value should be less than the Maximum Validity Duration  for Certificates (Days) setting on the Certificate Authority associated with this Mesh.  The certificate will be automatically renewed after 2/3 of the validity period, so a certificate with a maximum validity of 45 days will be renewed every 30 days.
     * 
     */
    public Integer maximumValidity() {
        return this.maximumValidity;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIngressGatewaysIngressGatewayCollectionItemMtl defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String certificateId;
        private Integer maximumValidity;
        public Builder() {}
        public Builder(GetIngressGatewaysIngressGatewayCollectionItemMtl defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.certificateId = defaults.certificateId;
    	      this.maximumValidity = defaults.maximumValidity;
        }

        @CustomType.Setter
        public Builder certificateId(String certificateId) {
            this.certificateId = Objects.requireNonNull(certificateId);
            return this;
        }
        @CustomType.Setter
        public Builder maximumValidity(Integer maximumValidity) {
            this.maximumValidity = Objects.requireNonNull(maximumValidity);
            return this;
        }
        public GetIngressGatewaysIngressGatewayCollectionItemMtl build() {
            final var o = new GetIngressGatewaysIngressGatewayCollectionItemMtl();
            o.certificateId = certificateId;
            o.maximumValidity = maximumValidity;
            return o;
        }
    }
}