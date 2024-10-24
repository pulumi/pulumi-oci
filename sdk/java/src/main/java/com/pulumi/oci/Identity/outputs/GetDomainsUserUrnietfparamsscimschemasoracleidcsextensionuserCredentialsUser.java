// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserApiKey;
import com.pulumi.oci.Identity.outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserAuthToken;
import com.pulumi.oci.Identity.outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserCustomerSecretKey;
import com.pulumi.oci.Identity.outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserDbCredential;
import com.pulumi.oci.Identity.outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserOAuth2clientCredential;
import com.pulumi.oci.Identity.outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserSmtpCredential;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUser {
    /**
     * @return A list of API keys corresponding to user.
     * 
     */
    private List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserApiKey> apiKeys;
    /**
     * @return A list of Auth tokens corresponding to user.
     * 
     */
    private List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserAuthToken> authTokens;
    /**
     * @return A list of customer secret keys corresponding to user.
     * 
     */
    private List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserCustomerSecretKey> customerSecretKeys;
    /**
     * @return A list of database credentials corresponding to user.
     * 
     */
    private List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserDbCredential> dbCredentials;
    /**
     * @return A list of OAuth2 client credentials corresponding to a user.
     * 
     */
    private List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserOAuth2clientCredential> oAuth2clientCredentials;
    /**
     * @return A list of SMTP credentials corresponding to user.
     * 
     */
    private List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserSmtpCredential> smtpCredentials;

    private GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUser() {}
    /**
     * @return A list of API keys corresponding to user.
     * 
     */
    public List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserApiKey> apiKeys() {
        return this.apiKeys;
    }
    /**
     * @return A list of Auth tokens corresponding to user.
     * 
     */
    public List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserAuthToken> authTokens() {
        return this.authTokens;
    }
    /**
     * @return A list of customer secret keys corresponding to user.
     * 
     */
    public List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserCustomerSecretKey> customerSecretKeys() {
        return this.customerSecretKeys;
    }
    /**
     * @return A list of database credentials corresponding to user.
     * 
     */
    public List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserDbCredential> dbCredentials() {
        return this.dbCredentials;
    }
    /**
     * @return A list of OAuth2 client credentials corresponding to a user.
     * 
     */
    public List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserOAuth2clientCredential> oAuth2clientCredentials() {
        return this.oAuth2clientCredentials;
    }
    /**
     * @return A list of SMTP credentials corresponding to user.
     * 
     */
    public List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserSmtpCredential> smtpCredentials() {
        return this.smtpCredentials;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUser defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserApiKey> apiKeys;
        private List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserAuthToken> authTokens;
        private List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserCustomerSecretKey> customerSecretKeys;
        private List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserDbCredential> dbCredentials;
        private List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserOAuth2clientCredential> oAuth2clientCredentials;
        private List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserSmtpCredential> smtpCredentials;
        public Builder() {}
        public Builder(GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUser defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apiKeys = defaults.apiKeys;
    	      this.authTokens = defaults.authTokens;
    	      this.customerSecretKeys = defaults.customerSecretKeys;
    	      this.dbCredentials = defaults.dbCredentials;
    	      this.oAuth2clientCredentials = defaults.oAuth2clientCredentials;
    	      this.smtpCredentials = defaults.smtpCredentials;
        }

        @CustomType.Setter
        public Builder apiKeys(List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserApiKey> apiKeys) {
            if (apiKeys == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUser", "apiKeys");
            }
            this.apiKeys = apiKeys;
            return this;
        }
        public Builder apiKeys(GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserApiKey... apiKeys) {
            return apiKeys(List.of(apiKeys));
        }
        @CustomType.Setter
        public Builder authTokens(List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserAuthToken> authTokens) {
            if (authTokens == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUser", "authTokens");
            }
            this.authTokens = authTokens;
            return this;
        }
        public Builder authTokens(GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserAuthToken... authTokens) {
            return authTokens(List.of(authTokens));
        }
        @CustomType.Setter
        public Builder customerSecretKeys(List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserCustomerSecretKey> customerSecretKeys) {
            if (customerSecretKeys == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUser", "customerSecretKeys");
            }
            this.customerSecretKeys = customerSecretKeys;
            return this;
        }
        public Builder customerSecretKeys(GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserCustomerSecretKey... customerSecretKeys) {
            return customerSecretKeys(List.of(customerSecretKeys));
        }
        @CustomType.Setter
        public Builder dbCredentials(List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserDbCredential> dbCredentials) {
            if (dbCredentials == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUser", "dbCredentials");
            }
            this.dbCredentials = dbCredentials;
            return this;
        }
        public Builder dbCredentials(GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserDbCredential... dbCredentials) {
            return dbCredentials(List.of(dbCredentials));
        }
        @CustomType.Setter
        public Builder oAuth2clientCredentials(List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserOAuth2clientCredential> oAuth2clientCredentials) {
            if (oAuth2clientCredentials == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUser", "oAuth2clientCredentials");
            }
            this.oAuth2clientCredentials = oAuth2clientCredentials;
            return this;
        }
        public Builder oAuth2clientCredentials(GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserOAuth2clientCredential... oAuth2clientCredentials) {
            return oAuth2clientCredentials(List.of(oAuth2clientCredentials));
        }
        @CustomType.Setter
        public Builder smtpCredentials(List<GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserSmtpCredential> smtpCredentials) {
            if (smtpCredentials == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUser", "smtpCredentials");
            }
            this.smtpCredentials = smtpCredentials;
            return this;
        }
        public Builder smtpCredentials(GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserSmtpCredential... smtpCredentials) {
            return smtpCredentials(List.of(smtpCredentials));
        }
        public GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUser build() {
            final var _resultValue = new GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUser();
            _resultValue.apiKeys = apiKeys;
            _resultValue.authTokens = authTokens;
            _resultValue.customerSecretKeys = customerSecretKeys;
            _resultValue.dbCredentials = dbCredentials;
            _resultValue.oAuth2clientCredentials = oAuth2clientCredentials;
            _resultValue.smtpCredentials = smtpCredentials;
            return _resultValue;
        }
    }
}
