// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionx509identityProvider {
    /**
     * @return X509 Certificate Matching Attribute
     * 
     */
    private String certMatchAttribute;
    /**
     * @return Fallback on CRL Validation if OCSP fails.
     * 
     */
    private Boolean crlCheckOnOcspFailureEnabled;
    /**
     * @return Set to true to enable CRL Validation
     * 
     */
    private Boolean crlEnabled;
    /**
     * @return CRL Location URL
     * 
     */
    private String crlLocation;
    /**
     * @return Fetch the CRL contents every X minutes
     * 
     */
    private Integer crlReloadDuration;
    /**
     * @return Allow access if OCSP response is UNKNOWN or OCSP Responder does not respond within the timeout duration
     * 
     */
    private Boolean ocspAllowUnknownResponseStatus;
    /**
     * @return Describes if the OCSP response is signed
     * 
     */
    private Boolean ocspEnableSignedResponse;
    /**
     * @return Set to true to enable OCSP Validation
     * 
     */
    private Boolean ocspEnabled;
    /**
     * @return This property specifies OCSP Responder URL.
     * 
     */
    private String ocspResponderUrl;
    /**
     * @return Revalidate OCSP status for user after X hours
     * 
     */
    private Integer ocspRevalidateTime;
    /**
     * @return This property specifies the OCSP Server alias name
     * 
     */
    private String ocspServerName;
    /**
     * @return OCSP Trusted Certificate Chain
     * 
     */
    private List<String> ocspTrustCertChains;
    /**
     * @return Check for specific conditions of other certificate attributes
     * 
     */
    private String otherCertMatchAttribute;
    /**
     * @return Certificate alias list to create a chain for the incoming client certificate
     * 
     */
    private List<String> signingCertificateChains;
    /**
     * @return This property specifies the userstore attribute value that must match the incoming certificate attribute.
     * 
     */
    private String userMatchAttribute;

    private GetDomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionx509identityProvider() {}
    /**
     * @return X509 Certificate Matching Attribute
     * 
     */
    public String certMatchAttribute() {
        return this.certMatchAttribute;
    }
    /**
     * @return Fallback on CRL Validation if OCSP fails.
     * 
     */
    public Boolean crlCheckOnOcspFailureEnabled() {
        return this.crlCheckOnOcspFailureEnabled;
    }
    /**
     * @return Set to true to enable CRL Validation
     * 
     */
    public Boolean crlEnabled() {
        return this.crlEnabled;
    }
    /**
     * @return CRL Location URL
     * 
     */
    public String crlLocation() {
        return this.crlLocation;
    }
    /**
     * @return Fetch the CRL contents every X minutes
     * 
     */
    public Integer crlReloadDuration() {
        return this.crlReloadDuration;
    }
    /**
     * @return Allow access if OCSP response is UNKNOWN or OCSP Responder does not respond within the timeout duration
     * 
     */
    public Boolean ocspAllowUnknownResponseStatus() {
        return this.ocspAllowUnknownResponseStatus;
    }
    /**
     * @return Describes if the OCSP response is signed
     * 
     */
    public Boolean ocspEnableSignedResponse() {
        return this.ocspEnableSignedResponse;
    }
    /**
     * @return Set to true to enable OCSP Validation
     * 
     */
    public Boolean ocspEnabled() {
        return this.ocspEnabled;
    }
    /**
     * @return This property specifies OCSP Responder URL.
     * 
     */
    public String ocspResponderUrl() {
        return this.ocspResponderUrl;
    }
    /**
     * @return Revalidate OCSP status for user after X hours
     * 
     */
    public Integer ocspRevalidateTime() {
        return this.ocspRevalidateTime;
    }
    /**
     * @return This property specifies the OCSP Server alias name
     * 
     */
    public String ocspServerName() {
        return this.ocspServerName;
    }
    /**
     * @return OCSP Trusted Certificate Chain
     * 
     */
    public List<String> ocspTrustCertChains() {
        return this.ocspTrustCertChains;
    }
    /**
     * @return Check for specific conditions of other certificate attributes
     * 
     */
    public String otherCertMatchAttribute() {
        return this.otherCertMatchAttribute;
    }
    /**
     * @return Certificate alias list to create a chain for the incoming client certificate
     * 
     */
    public List<String> signingCertificateChains() {
        return this.signingCertificateChains;
    }
    /**
     * @return This property specifies the userstore attribute value that must match the incoming certificate attribute.
     * 
     */
    public String userMatchAttribute() {
        return this.userMatchAttribute;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionx509identityProvider defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String certMatchAttribute;
        private Boolean crlCheckOnOcspFailureEnabled;
        private Boolean crlEnabled;
        private String crlLocation;
        private Integer crlReloadDuration;
        private Boolean ocspAllowUnknownResponseStatus;
        private Boolean ocspEnableSignedResponse;
        private Boolean ocspEnabled;
        private String ocspResponderUrl;
        private Integer ocspRevalidateTime;
        private String ocspServerName;
        private List<String> ocspTrustCertChains;
        private String otherCertMatchAttribute;
        private List<String> signingCertificateChains;
        private String userMatchAttribute;
        public Builder() {}
        public Builder(GetDomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionx509identityProvider defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.certMatchAttribute = defaults.certMatchAttribute;
    	      this.crlCheckOnOcspFailureEnabled = defaults.crlCheckOnOcspFailureEnabled;
    	      this.crlEnabled = defaults.crlEnabled;
    	      this.crlLocation = defaults.crlLocation;
    	      this.crlReloadDuration = defaults.crlReloadDuration;
    	      this.ocspAllowUnknownResponseStatus = defaults.ocspAllowUnknownResponseStatus;
    	      this.ocspEnableSignedResponse = defaults.ocspEnableSignedResponse;
    	      this.ocspEnabled = defaults.ocspEnabled;
    	      this.ocspResponderUrl = defaults.ocspResponderUrl;
    	      this.ocspRevalidateTime = defaults.ocspRevalidateTime;
    	      this.ocspServerName = defaults.ocspServerName;
    	      this.ocspTrustCertChains = defaults.ocspTrustCertChains;
    	      this.otherCertMatchAttribute = defaults.otherCertMatchAttribute;
    	      this.signingCertificateChains = defaults.signingCertificateChains;
    	      this.userMatchAttribute = defaults.userMatchAttribute;
        }

        @CustomType.Setter
        public Builder certMatchAttribute(String certMatchAttribute) {
            this.certMatchAttribute = Objects.requireNonNull(certMatchAttribute);
            return this;
        }
        @CustomType.Setter
        public Builder crlCheckOnOcspFailureEnabled(Boolean crlCheckOnOcspFailureEnabled) {
            this.crlCheckOnOcspFailureEnabled = Objects.requireNonNull(crlCheckOnOcspFailureEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder crlEnabled(Boolean crlEnabled) {
            this.crlEnabled = Objects.requireNonNull(crlEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder crlLocation(String crlLocation) {
            this.crlLocation = Objects.requireNonNull(crlLocation);
            return this;
        }
        @CustomType.Setter
        public Builder crlReloadDuration(Integer crlReloadDuration) {
            this.crlReloadDuration = Objects.requireNonNull(crlReloadDuration);
            return this;
        }
        @CustomType.Setter
        public Builder ocspAllowUnknownResponseStatus(Boolean ocspAllowUnknownResponseStatus) {
            this.ocspAllowUnknownResponseStatus = Objects.requireNonNull(ocspAllowUnknownResponseStatus);
            return this;
        }
        @CustomType.Setter
        public Builder ocspEnableSignedResponse(Boolean ocspEnableSignedResponse) {
            this.ocspEnableSignedResponse = Objects.requireNonNull(ocspEnableSignedResponse);
            return this;
        }
        @CustomType.Setter
        public Builder ocspEnabled(Boolean ocspEnabled) {
            this.ocspEnabled = Objects.requireNonNull(ocspEnabled);
            return this;
        }
        @CustomType.Setter
        public Builder ocspResponderUrl(String ocspResponderUrl) {
            this.ocspResponderUrl = Objects.requireNonNull(ocspResponderUrl);
            return this;
        }
        @CustomType.Setter
        public Builder ocspRevalidateTime(Integer ocspRevalidateTime) {
            this.ocspRevalidateTime = Objects.requireNonNull(ocspRevalidateTime);
            return this;
        }
        @CustomType.Setter
        public Builder ocspServerName(String ocspServerName) {
            this.ocspServerName = Objects.requireNonNull(ocspServerName);
            return this;
        }
        @CustomType.Setter
        public Builder ocspTrustCertChains(List<String> ocspTrustCertChains) {
            this.ocspTrustCertChains = Objects.requireNonNull(ocspTrustCertChains);
            return this;
        }
        public Builder ocspTrustCertChains(String... ocspTrustCertChains) {
            return ocspTrustCertChains(List.of(ocspTrustCertChains));
        }
        @CustomType.Setter
        public Builder otherCertMatchAttribute(String otherCertMatchAttribute) {
            this.otherCertMatchAttribute = Objects.requireNonNull(otherCertMatchAttribute);
            return this;
        }
        @CustomType.Setter
        public Builder signingCertificateChains(List<String> signingCertificateChains) {
            this.signingCertificateChains = Objects.requireNonNull(signingCertificateChains);
            return this;
        }
        public Builder signingCertificateChains(String... signingCertificateChains) {
            return signingCertificateChains(List.of(signingCertificateChains));
        }
        @CustomType.Setter
        public Builder userMatchAttribute(String userMatchAttribute) {
            this.userMatchAttribute = Objects.requireNonNull(userMatchAttribute);
            return this;
        }
        public GetDomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionx509identityProvider build() {
            final var o = new GetDomainsIdentityProviderUrnietfparamsscimschemasoracleidcsextensionx509identityProvider();
            o.certMatchAttribute = certMatchAttribute;
            o.crlCheckOnOcspFailureEnabled = crlCheckOnOcspFailureEnabled;
            o.crlEnabled = crlEnabled;
            o.crlLocation = crlLocation;
            o.crlReloadDuration = crlReloadDuration;
            o.ocspAllowUnknownResponseStatus = ocspAllowUnknownResponseStatus;
            o.ocspEnableSignedResponse = ocspEnableSignedResponse;
            o.ocspEnabled = ocspEnabled;
            o.ocspResponderUrl = ocspResponderUrl;
            o.ocspRevalidateTime = ocspRevalidateTime;
            o.ocspServerName = ocspServerName;
            o.ocspTrustCertChains = ocspTrustCertChains;
            o.otherCertMatchAttribute = otherCertMatchAttribute;
            o.signingCertificateChains = signingCertificateChains;
            o.userMatchAttribute = userMatchAttribute;
            return o;
        }
    }
}