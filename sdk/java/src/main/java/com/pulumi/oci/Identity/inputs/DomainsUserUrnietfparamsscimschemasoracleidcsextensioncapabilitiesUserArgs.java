// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsUserUrnietfparamsscimschemasoracleidcsextensioncapabilitiesUserArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsUserUrnietfparamsscimschemasoracleidcsextensioncapabilitiesUserArgs Empty = new DomainsUserUrnietfparamsscimschemasoracleidcsextensioncapabilitiesUserArgs();

    /**
     * (Updatable) Indicates weather a user can use api keys
     * 
     */
    @Import(name="canUseApiKeys")
    private @Nullable Output<Boolean> canUseApiKeys;

    /**
     * @return (Updatable) Indicates weather a user can use api keys
     * 
     */
    public Optional<Output<Boolean>> canUseApiKeys() {
        return Optional.ofNullable(this.canUseApiKeys);
    }

    /**
     * (Updatable) Indicates weather a user can use auth tokens
     * 
     */
    @Import(name="canUseAuthTokens")
    private @Nullable Output<Boolean> canUseAuthTokens;

    /**
     * @return (Updatable) Indicates weather a user can use auth tokens
     * 
     */
    public Optional<Output<Boolean>> canUseAuthTokens() {
        return Optional.ofNullable(this.canUseAuthTokens);
    }

    /**
     * (Updatable) Indicates weather a user can use console password
     * 
     */
    @Import(name="canUseConsolePassword")
    private @Nullable Output<Boolean> canUseConsolePassword;

    /**
     * @return (Updatable) Indicates weather a user can use console password
     * 
     */
    public Optional<Output<Boolean>> canUseConsolePassword() {
        return Optional.ofNullable(this.canUseConsolePassword);
    }

    /**
     * (Updatable) Indicates weather a user can use customer secret keys
     * 
     */
    @Import(name="canUseCustomerSecretKeys")
    private @Nullable Output<Boolean> canUseCustomerSecretKeys;

    /**
     * @return (Updatable) Indicates weather a user can use customer secret keys
     * 
     */
    public Optional<Output<Boolean>> canUseCustomerSecretKeys() {
        return Optional.ofNullable(this.canUseCustomerSecretKeys);
    }

    /**
     * (Updatable) Indicates weather a user can use db credentials
     * 
     */
    @Import(name="canUseDbCredentials")
    private @Nullable Output<Boolean> canUseDbCredentials;

    /**
     * @return (Updatable) Indicates weather a user can use db credentials
     * 
     */
    public Optional<Output<Boolean>> canUseDbCredentials() {
        return Optional.ofNullable(this.canUseDbCredentials);
    }

    /**
     * (Updatable) Indicates weather a user can use oauth2 client credentials
     * 
     */
    @Import(name="canUseOauth2clientCredentials")
    private @Nullable Output<Boolean> canUseOauth2clientCredentials;

    /**
     * @return (Updatable) Indicates weather a user can use oauth2 client credentials
     * 
     */
    public Optional<Output<Boolean>> canUseOauth2clientCredentials() {
        return Optional.ofNullable(this.canUseOauth2clientCredentials);
    }

    /**
     * (Updatable) Indicates weather a user can use smtp credentials
     * 
     */
    @Import(name="canUseSmtpCredentials")
    private @Nullable Output<Boolean> canUseSmtpCredentials;

    /**
     * @return (Updatable) Indicates weather a user can use smtp credentials
     * 
     */
    public Optional<Output<Boolean>> canUseSmtpCredentials() {
        return Optional.ofNullable(this.canUseSmtpCredentials);
    }

    private DomainsUserUrnietfparamsscimschemasoracleidcsextensioncapabilitiesUserArgs() {}

    private DomainsUserUrnietfparamsscimschemasoracleidcsextensioncapabilitiesUserArgs(DomainsUserUrnietfparamsscimschemasoracleidcsextensioncapabilitiesUserArgs $) {
        this.canUseApiKeys = $.canUseApiKeys;
        this.canUseAuthTokens = $.canUseAuthTokens;
        this.canUseConsolePassword = $.canUseConsolePassword;
        this.canUseCustomerSecretKeys = $.canUseCustomerSecretKeys;
        this.canUseDbCredentials = $.canUseDbCredentials;
        this.canUseOauth2clientCredentials = $.canUseOauth2clientCredentials;
        this.canUseSmtpCredentials = $.canUseSmtpCredentials;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsUserUrnietfparamsscimschemasoracleidcsextensioncapabilitiesUserArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensioncapabilitiesUserArgs $;

        public Builder() {
            $ = new DomainsUserUrnietfparamsscimschemasoracleidcsextensioncapabilitiesUserArgs();
        }

        public Builder(DomainsUserUrnietfparamsscimschemasoracleidcsextensioncapabilitiesUserArgs defaults) {
            $ = new DomainsUserUrnietfparamsscimschemasoracleidcsextensioncapabilitiesUserArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param canUseApiKeys (Updatable) Indicates weather a user can use api keys
         * 
         * @return builder
         * 
         */
        public Builder canUseApiKeys(@Nullable Output<Boolean> canUseApiKeys) {
            $.canUseApiKeys = canUseApiKeys;
            return this;
        }

        /**
         * @param canUseApiKeys (Updatable) Indicates weather a user can use api keys
         * 
         * @return builder
         * 
         */
        public Builder canUseApiKeys(Boolean canUseApiKeys) {
            return canUseApiKeys(Output.of(canUseApiKeys));
        }

        /**
         * @param canUseAuthTokens (Updatable) Indicates weather a user can use auth tokens
         * 
         * @return builder
         * 
         */
        public Builder canUseAuthTokens(@Nullable Output<Boolean> canUseAuthTokens) {
            $.canUseAuthTokens = canUseAuthTokens;
            return this;
        }

        /**
         * @param canUseAuthTokens (Updatable) Indicates weather a user can use auth tokens
         * 
         * @return builder
         * 
         */
        public Builder canUseAuthTokens(Boolean canUseAuthTokens) {
            return canUseAuthTokens(Output.of(canUseAuthTokens));
        }

        /**
         * @param canUseConsolePassword (Updatable) Indicates weather a user can use console password
         * 
         * @return builder
         * 
         */
        public Builder canUseConsolePassword(@Nullable Output<Boolean> canUseConsolePassword) {
            $.canUseConsolePassword = canUseConsolePassword;
            return this;
        }

        /**
         * @param canUseConsolePassword (Updatable) Indicates weather a user can use console password
         * 
         * @return builder
         * 
         */
        public Builder canUseConsolePassword(Boolean canUseConsolePassword) {
            return canUseConsolePassword(Output.of(canUseConsolePassword));
        }

        /**
         * @param canUseCustomerSecretKeys (Updatable) Indicates weather a user can use customer secret keys
         * 
         * @return builder
         * 
         */
        public Builder canUseCustomerSecretKeys(@Nullable Output<Boolean> canUseCustomerSecretKeys) {
            $.canUseCustomerSecretKeys = canUseCustomerSecretKeys;
            return this;
        }

        /**
         * @param canUseCustomerSecretKeys (Updatable) Indicates weather a user can use customer secret keys
         * 
         * @return builder
         * 
         */
        public Builder canUseCustomerSecretKeys(Boolean canUseCustomerSecretKeys) {
            return canUseCustomerSecretKeys(Output.of(canUseCustomerSecretKeys));
        }

        /**
         * @param canUseDbCredentials (Updatable) Indicates weather a user can use db credentials
         * 
         * @return builder
         * 
         */
        public Builder canUseDbCredentials(@Nullable Output<Boolean> canUseDbCredentials) {
            $.canUseDbCredentials = canUseDbCredentials;
            return this;
        }

        /**
         * @param canUseDbCredentials (Updatable) Indicates weather a user can use db credentials
         * 
         * @return builder
         * 
         */
        public Builder canUseDbCredentials(Boolean canUseDbCredentials) {
            return canUseDbCredentials(Output.of(canUseDbCredentials));
        }

        /**
         * @param canUseOauth2clientCredentials (Updatable) Indicates weather a user can use oauth2 client credentials
         * 
         * @return builder
         * 
         */
        public Builder canUseOauth2clientCredentials(@Nullable Output<Boolean> canUseOauth2clientCredentials) {
            $.canUseOauth2clientCredentials = canUseOauth2clientCredentials;
            return this;
        }

        /**
         * @param canUseOauth2clientCredentials (Updatable) Indicates weather a user can use oauth2 client credentials
         * 
         * @return builder
         * 
         */
        public Builder canUseOauth2clientCredentials(Boolean canUseOauth2clientCredentials) {
            return canUseOauth2clientCredentials(Output.of(canUseOauth2clientCredentials));
        }

        /**
         * @param canUseSmtpCredentials (Updatable) Indicates weather a user can use smtp credentials
         * 
         * @return builder
         * 
         */
        public Builder canUseSmtpCredentials(@Nullable Output<Boolean> canUseSmtpCredentials) {
            $.canUseSmtpCredentials = canUseSmtpCredentials;
            return this;
        }

        /**
         * @param canUseSmtpCredentials (Updatable) Indicates weather a user can use smtp credentials
         * 
         * @return builder
         * 
         */
        public Builder canUseSmtpCredentials(Boolean canUseSmtpCredentials) {
            return canUseSmtpCredentials(Output.of(canUseSmtpCredentials));
        }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensioncapabilitiesUserArgs build() {
            return $;
        }
    }

}