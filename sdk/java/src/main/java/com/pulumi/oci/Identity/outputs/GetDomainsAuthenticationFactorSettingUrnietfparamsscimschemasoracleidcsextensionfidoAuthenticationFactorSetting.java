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
public final class GetDomainsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionfidoAuthenticationFactorSetting {
    /**
     * @return Attribute used to define the type of attestation required.
     * 
     */
    private String attestation;
    /**
     * @return Attribute used to define authenticator selection attachment.
     * 
     */
    private String authenticatorSelectionAttachment;
    /**
     * @return Flag used to indicate authenticator selection is required or not
     * 
     */
    private Boolean authenticatorSelectionRequireResidentKey;
    /**
     * @return Attribute used to define authenticator selection resident key requirement.
     * 
     */
    private String authenticatorSelectionResidentKey;
    /**
     * @return Attribute used to define authenticator selection verification.
     * 
     */
    private String authenticatorSelectionUserVerification;
    /**
     * @return Number of domain levels IDCS should use for origin comparision
     * 
     */
    private Integer domainValidationLevel;
    /**
     * @return Flag used to indicate whether we need to restrict creation of multiple credentials in same authenticator
     * 
     */
    private Boolean excludeCredentials;
    /**
     * @return List of server supported public key algorithms
     * 
     */
    private List<String> publicKeyTypes;
    /**
     * @return Timeout for the fido authentication to complete
     * 
     */
    private Integer timeout;

    private GetDomainsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionfidoAuthenticationFactorSetting() {}
    /**
     * @return Attribute used to define the type of attestation required.
     * 
     */
    public String attestation() {
        return this.attestation;
    }
    /**
     * @return Attribute used to define authenticator selection attachment.
     * 
     */
    public String authenticatorSelectionAttachment() {
        return this.authenticatorSelectionAttachment;
    }
    /**
     * @return Flag used to indicate authenticator selection is required or not
     * 
     */
    public Boolean authenticatorSelectionRequireResidentKey() {
        return this.authenticatorSelectionRequireResidentKey;
    }
    /**
     * @return Attribute used to define authenticator selection resident key requirement.
     * 
     */
    public String authenticatorSelectionResidentKey() {
        return this.authenticatorSelectionResidentKey;
    }
    /**
     * @return Attribute used to define authenticator selection verification.
     * 
     */
    public String authenticatorSelectionUserVerification() {
        return this.authenticatorSelectionUserVerification;
    }
    /**
     * @return Number of domain levels IDCS should use for origin comparision
     * 
     */
    public Integer domainValidationLevel() {
        return this.domainValidationLevel;
    }
    /**
     * @return Flag used to indicate whether we need to restrict creation of multiple credentials in same authenticator
     * 
     */
    public Boolean excludeCredentials() {
        return this.excludeCredentials;
    }
    /**
     * @return List of server supported public key algorithms
     * 
     */
    public List<String> publicKeyTypes() {
        return this.publicKeyTypes;
    }
    /**
     * @return Timeout for the fido authentication to complete
     * 
     */
    public Integer timeout() {
        return this.timeout;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionfidoAuthenticationFactorSetting defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String attestation;
        private String authenticatorSelectionAttachment;
        private Boolean authenticatorSelectionRequireResidentKey;
        private String authenticatorSelectionResidentKey;
        private String authenticatorSelectionUserVerification;
        private Integer domainValidationLevel;
        private Boolean excludeCredentials;
        private List<String> publicKeyTypes;
        private Integer timeout;
        public Builder() {}
        public Builder(GetDomainsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionfidoAuthenticationFactorSetting defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.attestation = defaults.attestation;
    	      this.authenticatorSelectionAttachment = defaults.authenticatorSelectionAttachment;
    	      this.authenticatorSelectionRequireResidentKey = defaults.authenticatorSelectionRequireResidentKey;
    	      this.authenticatorSelectionResidentKey = defaults.authenticatorSelectionResidentKey;
    	      this.authenticatorSelectionUserVerification = defaults.authenticatorSelectionUserVerification;
    	      this.domainValidationLevel = defaults.domainValidationLevel;
    	      this.excludeCredentials = defaults.excludeCredentials;
    	      this.publicKeyTypes = defaults.publicKeyTypes;
    	      this.timeout = defaults.timeout;
        }

        @CustomType.Setter
        public Builder attestation(String attestation) {
            this.attestation = Objects.requireNonNull(attestation);
            return this;
        }
        @CustomType.Setter
        public Builder authenticatorSelectionAttachment(String authenticatorSelectionAttachment) {
            this.authenticatorSelectionAttachment = Objects.requireNonNull(authenticatorSelectionAttachment);
            return this;
        }
        @CustomType.Setter
        public Builder authenticatorSelectionRequireResidentKey(Boolean authenticatorSelectionRequireResidentKey) {
            this.authenticatorSelectionRequireResidentKey = Objects.requireNonNull(authenticatorSelectionRequireResidentKey);
            return this;
        }
        @CustomType.Setter
        public Builder authenticatorSelectionResidentKey(String authenticatorSelectionResidentKey) {
            this.authenticatorSelectionResidentKey = Objects.requireNonNull(authenticatorSelectionResidentKey);
            return this;
        }
        @CustomType.Setter
        public Builder authenticatorSelectionUserVerification(String authenticatorSelectionUserVerification) {
            this.authenticatorSelectionUserVerification = Objects.requireNonNull(authenticatorSelectionUserVerification);
            return this;
        }
        @CustomType.Setter
        public Builder domainValidationLevel(Integer domainValidationLevel) {
            this.domainValidationLevel = Objects.requireNonNull(domainValidationLevel);
            return this;
        }
        @CustomType.Setter
        public Builder excludeCredentials(Boolean excludeCredentials) {
            this.excludeCredentials = Objects.requireNonNull(excludeCredentials);
            return this;
        }
        @CustomType.Setter
        public Builder publicKeyTypes(List<String> publicKeyTypes) {
            this.publicKeyTypes = Objects.requireNonNull(publicKeyTypes);
            return this;
        }
        public Builder publicKeyTypes(String... publicKeyTypes) {
            return publicKeyTypes(List.of(publicKeyTypes));
        }
        @CustomType.Setter
        public Builder timeout(Integer timeout) {
            this.timeout = Objects.requireNonNull(timeout);
            return this;
        }
        public GetDomainsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionfidoAuthenticationFactorSetting build() {
            final var o = new GetDomainsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionfidoAuthenticationFactorSetting();
            o.attestation = attestation;
            o.authenticatorSelectionAttachment = authenticatorSelectionAttachment;
            o.authenticatorSelectionRequireResidentKey = authenticatorSelectionRequireResidentKey;
            o.authenticatorSelectionResidentKey = authenticatorSelectionResidentKey;
            o.authenticatorSelectionUserVerification = authenticatorSelectionUserVerification;
            o.domainValidationLevel = domainValidationLevel;
            o.excludeCredentials = excludeCredentials;
            o.publicKeyTypes = publicKeyTypes;
            o.timeout = timeout;
            return o;
        }
    }
}