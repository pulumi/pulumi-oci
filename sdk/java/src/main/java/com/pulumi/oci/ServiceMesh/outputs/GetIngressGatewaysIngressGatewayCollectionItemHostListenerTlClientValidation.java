// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ServiceMesh.outputs.GetIngressGatewaysIngressGatewayCollectionItemHostListenerTlClientValidationTrustedCaBundle;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetIngressGatewaysIngressGatewayCollectionItemHostListenerTlClientValidation {
    /**
     * @return A list of alternate names to verify the subject identity in the certificate presented by the client.
     * 
     */
    private List<String> subjectAlternateNames;
    /**
     * @return Resource representing the CA bundle.
     * 
     */
    private List<GetIngressGatewaysIngressGatewayCollectionItemHostListenerTlClientValidationTrustedCaBundle> trustedCaBundles;

    private GetIngressGatewaysIngressGatewayCollectionItemHostListenerTlClientValidation() {}
    /**
     * @return A list of alternate names to verify the subject identity in the certificate presented by the client.
     * 
     */
    public List<String> subjectAlternateNames() {
        return this.subjectAlternateNames;
    }
    /**
     * @return Resource representing the CA bundle.
     * 
     */
    public List<GetIngressGatewaysIngressGatewayCollectionItemHostListenerTlClientValidationTrustedCaBundle> trustedCaBundles() {
        return this.trustedCaBundles;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIngressGatewaysIngressGatewayCollectionItemHostListenerTlClientValidation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> subjectAlternateNames;
        private List<GetIngressGatewaysIngressGatewayCollectionItemHostListenerTlClientValidationTrustedCaBundle> trustedCaBundles;
        public Builder() {}
        public Builder(GetIngressGatewaysIngressGatewayCollectionItemHostListenerTlClientValidation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.subjectAlternateNames = defaults.subjectAlternateNames;
    	      this.trustedCaBundles = defaults.trustedCaBundles;
        }

        @CustomType.Setter
        public Builder subjectAlternateNames(List<String> subjectAlternateNames) {
            this.subjectAlternateNames = Objects.requireNonNull(subjectAlternateNames);
            return this;
        }
        public Builder subjectAlternateNames(String... subjectAlternateNames) {
            return subjectAlternateNames(List.of(subjectAlternateNames));
        }
        @CustomType.Setter
        public Builder trustedCaBundles(List<GetIngressGatewaysIngressGatewayCollectionItemHostListenerTlClientValidationTrustedCaBundle> trustedCaBundles) {
            this.trustedCaBundles = Objects.requireNonNull(trustedCaBundles);
            return this;
        }
        public Builder trustedCaBundles(GetIngressGatewaysIngressGatewayCollectionItemHostListenerTlClientValidationTrustedCaBundle... trustedCaBundles) {
            return trustedCaBundles(List.of(trustedCaBundles));
        }
        public GetIngressGatewaysIngressGatewayCollectionItemHostListenerTlClientValidation build() {
            final var o = new GetIngressGatewaysIngressGatewayCollectionItemHostListenerTlClientValidation();
            o.subjectAlternateNames = subjectAlternateNames;
            o.trustedCaBundles = trustedCaBundles;
            return o;
        }
    }
}