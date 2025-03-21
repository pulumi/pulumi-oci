// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ApmSynthetics.inputs.ConfigConfigurationDatabaseAuthenticationDetailsPasswordArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConfigConfigurationDatabaseAuthenticationDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConfigConfigurationDatabaseAuthenticationDetailsArgs Empty = new ConfigConfigurationDatabaseAuthenticationDetailsArgs();

    /**
     * (Updatable) Password.
     * 
     */
    @Import(name="password")
    private @Nullable Output<ConfigConfigurationDatabaseAuthenticationDetailsPasswordArgs> password;

    /**
     * @return (Updatable) Password.
     * 
     */
    public Optional<Output<ConfigConfigurationDatabaseAuthenticationDetailsPasswordArgs>> password() {
        return Optional.ofNullable(this.password);
    }

    /**
     * (Updatable) Username for authentication.
     * 
     */
    @Import(name="username")
    private @Nullable Output<String> username;

    /**
     * @return (Updatable) Username for authentication.
     * 
     */
    public Optional<Output<String>> username() {
        return Optional.ofNullable(this.username);
    }

    private ConfigConfigurationDatabaseAuthenticationDetailsArgs() {}

    private ConfigConfigurationDatabaseAuthenticationDetailsArgs(ConfigConfigurationDatabaseAuthenticationDetailsArgs $) {
        this.password = $.password;
        this.username = $.username;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConfigConfigurationDatabaseAuthenticationDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConfigConfigurationDatabaseAuthenticationDetailsArgs $;

        public Builder() {
            $ = new ConfigConfigurationDatabaseAuthenticationDetailsArgs();
        }

        public Builder(ConfigConfigurationDatabaseAuthenticationDetailsArgs defaults) {
            $ = new ConfigConfigurationDatabaseAuthenticationDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param password (Updatable) Password.
         * 
         * @return builder
         * 
         */
        public Builder password(@Nullable Output<ConfigConfigurationDatabaseAuthenticationDetailsPasswordArgs> password) {
            $.password = password;
            return this;
        }

        /**
         * @param password (Updatable) Password.
         * 
         * @return builder
         * 
         */
        public Builder password(ConfigConfigurationDatabaseAuthenticationDetailsPasswordArgs password) {
            return password(Output.of(password));
        }

        /**
         * @param username (Updatable) Username for authentication.
         * 
         * @return builder
         * 
         */
        public Builder username(@Nullable Output<String> username) {
            $.username = username;
            return this;
        }

        /**
         * @param username (Updatable) Username for authentication.
         * 
         * @return builder
         * 
         */
        public Builder username(String username) {
            return username(Output.of(username));
        }

        public ConfigConfigurationDatabaseAuthenticationDetailsArgs build() {
            return $;
        }
    }

}
