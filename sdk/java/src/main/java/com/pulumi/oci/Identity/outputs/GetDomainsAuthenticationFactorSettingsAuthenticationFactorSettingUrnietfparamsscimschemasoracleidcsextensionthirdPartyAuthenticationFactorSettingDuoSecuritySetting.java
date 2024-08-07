// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettingDuoSecuritySetting {
    /**
     * @return Hostname to access the Duo security account
     * 
     */
    private String apiHostname;
    /**
     * @return Attestation key to attest the request and response between Duo Security
     * 
     */
    private String attestationKey;
    /**
     * @return Integration key from Duo Security authenticator
     * 
     */
    private String integrationKey;
    /**
     * @return Secret key from Duo Security authenticator
     * 
     */
    private String secretKey;
    /**
     * @return User attribute mapping value
     * 
     */
    private String userMappingAttribute;

    private GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettingDuoSecuritySetting() {}
    /**
     * @return Hostname to access the Duo security account
     * 
     */
    public String apiHostname() {
        return this.apiHostname;
    }
    /**
     * @return Attestation key to attest the request and response between Duo Security
     * 
     */
    public String attestationKey() {
        return this.attestationKey;
    }
    /**
     * @return Integration key from Duo Security authenticator
     * 
     */
    public String integrationKey() {
        return this.integrationKey;
    }
    /**
     * @return Secret key from Duo Security authenticator
     * 
     */
    public String secretKey() {
        return this.secretKey;
    }
    /**
     * @return User attribute mapping value
     * 
     */
    public String userMappingAttribute() {
        return this.userMappingAttribute;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettingDuoSecuritySetting defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String apiHostname;
        private String attestationKey;
        private String integrationKey;
        private String secretKey;
        private String userMappingAttribute;
        public Builder() {}
        public Builder(GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettingDuoSecuritySetting defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apiHostname = defaults.apiHostname;
    	      this.attestationKey = defaults.attestationKey;
    	      this.integrationKey = defaults.integrationKey;
    	      this.secretKey = defaults.secretKey;
    	      this.userMappingAttribute = defaults.userMappingAttribute;
        }

        @CustomType.Setter
        public Builder apiHostname(String apiHostname) {
            if (apiHostname == null) {
              throw new MissingRequiredPropertyException("GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettingDuoSecuritySetting", "apiHostname");
            }
            this.apiHostname = apiHostname;
            return this;
        }
        @CustomType.Setter
        public Builder attestationKey(String attestationKey) {
            if (attestationKey == null) {
              throw new MissingRequiredPropertyException("GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettingDuoSecuritySetting", "attestationKey");
            }
            this.attestationKey = attestationKey;
            return this;
        }
        @CustomType.Setter
        public Builder integrationKey(String integrationKey) {
            if (integrationKey == null) {
              throw new MissingRequiredPropertyException("GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettingDuoSecuritySetting", "integrationKey");
            }
            this.integrationKey = integrationKey;
            return this;
        }
        @CustomType.Setter
        public Builder secretKey(String secretKey) {
            if (secretKey == null) {
              throw new MissingRequiredPropertyException("GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettingDuoSecuritySetting", "secretKey");
            }
            this.secretKey = secretKey;
            return this;
        }
        @CustomType.Setter
        public Builder userMappingAttribute(String userMappingAttribute) {
            if (userMappingAttribute == null) {
              throw new MissingRequiredPropertyException("GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettingDuoSecuritySetting", "userMappingAttribute");
            }
            this.userMappingAttribute = userMappingAttribute;
            return this;
        }
        public GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettingDuoSecuritySetting build() {
            final var _resultValue = new GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettingDuoSecuritySetting();
            _resultValue.apiHostname = apiHostname;
            _resultValue.attestationKey = attestationKey;
            _resultValue.integrationKey = integrationKey;
            _resultValue.secretKey = secretKey;
            _resultValue.userMappingAttribute = userMappingAttribute;
            return _resultValue;
        }
    }
}
