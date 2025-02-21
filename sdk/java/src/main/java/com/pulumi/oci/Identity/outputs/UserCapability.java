// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class UserCapability {
    /**
     * @return Indicates if the user can use API keys.
     * 
     */
    private @Nullable Boolean canUseApiKeys;
    /**
     * @return Indicates if the user can use SWIFT passwords / auth tokens.
     * 
     */
    private @Nullable Boolean canUseAuthTokens;
    /**
     * @return Indicates if the user can log in to the console.
     * 
     */
    private @Nullable Boolean canUseConsolePassword;
    /**
     * @return Indicates if the user can use SigV4 symmetric keys.
     * 
     */
    private @Nullable Boolean canUseCustomerSecretKeys;
    /**
     * @return Indicates if the user can use DB passwords.
     * 
     */
    private @Nullable Boolean canUseDbCredentials;
    /**
     * @return Indicates if the user can use OAuth2 credentials and tokens.
     * 
     */
    private @Nullable Boolean canUseOauth2clientCredentials;
    /**
     * @return Indicates if the user can use SMTP passwords.
     * 
     */
    private @Nullable Boolean canUseSmtpCredentials;

    private UserCapability() {}
    /**
     * @return Indicates if the user can use API keys.
     * 
     */
    public Optional<Boolean> canUseApiKeys() {
        return Optional.ofNullable(this.canUseApiKeys);
    }
    /**
     * @return Indicates if the user can use SWIFT passwords / auth tokens.
     * 
     */
    public Optional<Boolean> canUseAuthTokens() {
        return Optional.ofNullable(this.canUseAuthTokens);
    }
    /**
     * @return Indicates if the user can log in to the console.
     * 
     */
    public Optional<Boolean> canUseConsolePassword() {
        return Optional.ofNullable(this.canUseConsolePassword);
    }
    /**
     * @return Indicates if the user can use SigV4 symmetric keys.
     * 
     */
    public Optional<Boolean> canUseCustomerSecretKeys() {
        return Optional.ofNullable(this.canUseCustomerSecretKeys);
    }
    /**
     * @return Indicates if the user can use DB passwords.
     * 
     */
    public Optional<Boolean> canUseDbCredentials() {
        return Optional.ofNullable(this.canUseDbCredentials);
    }
    /**
     * @return Indicates if the user can use OAuth2 credentials and tokens.
     * 
     */
    public Optional<Boolean> canUseOauth2clientCredentials() {
        return Optional.ofNullable(this.canUseOauth2clientCredentials);
    }
    /**
     * @return Indicates if the user can use SMTP passwords.
     * 
     */
    public Optional<Boolean> canUseSmtpCredentials() {
        return Optional.ofNullable(this.canUseSmtpCredentials);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(UserCapability defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean canUseApiKeys;
        private @Nullable Boolean canUseAuthTokens;
        private @Nullable Boolean canUseConsolePassword;
        private @Nullable Boolean canUseCustomerSecretKeys;
        private @Nullable Boolean canUseDbCredentials;
        private @Nullable Boolean canUseOauth2clientCredentials;
        private @Nullable Boolean canUseSmtpCredentials;
        public Builder() {}
        public Builder(UserCapability defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.canUseApiKeys = defaults.canUseApiKeys;
    	      this.canUseAuthTokens = defaults.canUseAuthTokens;
    	      this.canUseConsolePassword = defaults.canUseConsolePassword;
    	      this.canUseCustomerSecretKeys = defaults.canUseCustomerSecretKeys;
    	      this.canUseDbCredentials = defaults.canUseDbCredentials;
    	      this.canUseOauth2clientCredentials = defaults.canUseOauth2clientCredentials;
    	      this.canUseSmtpCredentials = defaults.canUseSmtpCredentials;
        }

        @CustomType.Setter
        public Builder canUseApiKeys(@Nullable Boolean canUseApiKeys) {

            this.canUseApiKeys = canUseApiKeys;
            return this;
        }
        @CustomType.Setter
        public Builder canUseAuthTokens(@Nullable Boolean canUseAuthTokens) {

            this.canUseAuthTokens = canUseAuthTokens;
            return this;
        }
        @CustomType.Setter
        public Builder canUseConsolePassword(@Nullable Boolean canUseConsolePassword) {

            this.canUseConsolePassword = canUseConsolePassword;
            return this;
        }
        @CustomType.Setter
        public Builder canUseCustomerSecretKeys(@Nullable Boolean canUseCustomerSecretKeys) {

            this.canUseCustomerSecretKeys = canUseCustomerSecretKeys;
            return this;
        }
        @CustomType.Setter
        public Builder canUseDbCredentials(@Nullable Boolean canUseDbCredentials) {

            this.canUseDbCredentials = canUseDbCredentials;
            return this;
        }
        @CustomType.Setter
        public Builder canUseOauth2clientCredentials(@Nullable Boolean canUseOauth2clientCredentials) {

            this.canUseOauth2clientCredentials = canUseOauth2clientCredentials;
            return this;
        }
        @CustomType.Setter
        public Builder canUseSmtpCredentials(@Nullable Boolean canUseSmtpCredentials) {

            this.canUseSmtpCredentials = canUseSmtpCredentials;
            return this;
        }
        public UserCapability build() {
            final var _resultValue = new UserCapability();
            _resultValue.canUseApiKeys = canUseApiKeys;
            _resultValue.canUseAuthTokens = canUseAuthTokens;
            _resultValue.canUseConsolePassword = canUseConsolePassword;
            _resultValue.canUseCustomerSecretKeys = canUseCustomerSecretKeys;
            _resultValue.canUseDbCredentials = canUseDbCredentials;
            _resultValue.canUseOauth2clientCredentials = canUseOauth2clientCredentials;
            _resultValue.canUseSmtpCredentials = canUseSmtpCredentials;
            return _resultValue;
        }
    }
}
