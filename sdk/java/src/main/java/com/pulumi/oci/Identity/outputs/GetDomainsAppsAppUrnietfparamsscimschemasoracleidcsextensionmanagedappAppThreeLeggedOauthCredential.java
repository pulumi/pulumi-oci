// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppThreeLeggedOauthCredential {
    /**
     * @return Access Token
     * 
     */
    private String accessToken;
    /**
     * @return Access token expiry
     * 
     */
    private String accessTokenExpiry;
    /**
     * @return Refresh Token
     * 
     */
    private String refreshToken;

    private GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppThreeLeggedOauthCredential() {}
    /**
     * @return Access Token
     * 
     */
    public String accessToken() {
        return this.accessToken;
    }
    /**
     * @return Access token expiry
     * 
     */
    public String accessTokenExpiry() {
        return this.accessTokenExpiry;
    }
    /**
     * @return Refresh Token
     * 
     */
    public String refreshToken() {
        return this.refreshToken;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppThreeLeggedOauthCredential defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String accessToken;
        private String accessTokenExpiry;
        private String refreshToken;
        public Builder() {}
        public Builder(GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppThreeLeggedOauthCredential defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessToken = defaults.accessToken;
    	      this.accessTokenExpiry = defaults.accessTokenExpiry;
    	      this.refreshToken = defaults.refreshToken;
        }

        @CustomType.Setter
        public Builder accessToken(String accessToken) {
            if (accessToken == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppThreeLeggedOauthCredential", "accessToken");
            }
            this.accessToken = accessToken;
            return this;
        }
        @CustomType.Setter
        public Builder accessTokenExpiry(String accessTokenExpiry) {
            if (accessTokenExpiry == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppThreeLeggedOauthCredential", "accessTokenExpiry");
            }
            this.accessTokenExpiry = accessTokenExpiry;
            return this;
        }
        @CustomType.Setter
        public Builder refreshToken(String refreshToken) {
            if (refreshToken == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppThreeLeggedOauthCredential", "refreshToken");
            }
            this.refreshToken = refreshToken;
            return this;
        }
        public GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppThreeLeggedOauthCredential build() {
            final var _resultValue = new GetDomainsAppsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppThreeLeggedOauthCredential();
            _resultValue.accessToken = accessToken;
            _resultValue.accessTokenExpiry = accessTokenExpiry;
            _resultValue.refreshToken = refreshToken;
            return _resultValue;
        }
    }
}
