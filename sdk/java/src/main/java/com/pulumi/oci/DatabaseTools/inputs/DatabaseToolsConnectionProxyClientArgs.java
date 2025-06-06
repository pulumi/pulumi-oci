// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseTools.inputs.DatabaseToolsConnectionProxyClientUserPasswordArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DatabaseToolsConnectionProxyClientArgs extends com.pulumi.resources.ResourceArgs {

    public static final DatabaseToolsConnectionProxyClientArgs Empty = new DatabaseToolsConnectionProxyClientArgs();

    /**
     * (Updatable) The proxy authentication type.
     * 
     */
    @Import(name="proxyAuthenticationType", required=true)
    private Output<String> proxyAuthenticationType;

    /**
     * @return (Updatable) The proxy authentication type.
     * 
     */
    public Output<String> proxyAuthenticationType() {
        return this.proxyAuthenticationType;
    }

    /**
     * (Updatable) A list of database roles for the client. These roles are enabled if the proxy is authorized to use the roles on behalf of the client.
     * 
     */
    @Import(name="roles")
    private @Nullable Output<List<String>> roles;

    /**
     * @return (Updatable) A list of database roles for the client. These roles are enabled if the proxy is authorized to use the roles on behalf of the client.
     * 
     */
    public Optional<Output<List<String>>> roles() {
        return Optional.ofNullable(this.roles);
    }

    /**
     * (Updatable) The user name.
     * 
     */
    @Import(name="userName")
    private @Nullable Output<String> userName;

    /**
     * @return (Updatable) The user name.
     * 
     */
    public Optional<Output<String>> userName() {
        return Optional.ofNullable(this.userName);
    }

    /**
     * (Updatable) The user password.
     * 
     */
    @Import(name="userPassword")
    private @Nullable Output<DatabaseToolsConnectionProxyClientUserPasswordArgs> userPassword;

    /**
     * @return (Updatable) The user password.
     * 
     */
    public Optional<Output<DatabaseToolsConnectionProxyClientUserPasswordArgs>> userPassword() {
        return Optional.ofNullable(this.userPassword);
    }

    private DatabaseToolsConnectionProxyClientArgs() {}

    private DatabaseToolsConnectionProxyClientArgs(DatabaseToolsConnectionProxyClientArgs $) {
        this.proxyAuthenticationType = $.proxyAuthenticationType;
        this.roles = $.roles;
        this.userName = $.userName;
        this.userPassword = $.userPassword;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DatabaseToolsConnectionProxyClientArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DatabaseToolsConnectionProxyClientArgs $;

        public Builder() {
            $ = new DatabaseToolsConnectionProxyClientArgs();
        }

        public Builder(DatabaseToolsConnectionProxyClientArgs defaults) {
            $ = new DatabaseToolsConnectionProxyClientArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param proxyAuthenticationType (Updatable) The proxy authentication type.
         * 
         * @return builder
         * 
         */
        public Builder proxyAuthenticationType(Output<String> proxyAuthenticationType) {
            $.proxyAuthenticationType = proxyAuthenticationType;
            return this;
        }

        /**
         * @param proxyAuthenticationType (Updatable) The proxy authentication type.
         * 
         * @return builder
         * 
         */
        public Builder proxyAuthenticationType(String proxyAuthenticationType) {
            return proxyAuthenticationType(Output.of(proxyAuthenticationType));
        }

        /**
         * @param roles (Updatable) A list of database roles for the client. These roles are enabled if the proxy is authorized to use the roles on behalf of the client.
         * 
         * @return builder
         * 
         */
        public Builder roles(@Nullable Output<List<String>> roles) {
            $.roles = roles;
            return this;
        }

        /**
         * @param roles (Updatable) A list of database roles for the client. These roles are enabled if the proxy is authorized to use the roles on behalf of the client.
         * 
         * @return builder
         * 
         */
        public Builder roles(List<String> roles) {
            return roles(Output.of(roles));
        }

        /**
         * @param roles (Updatable) A list of database roles for the client. These roles are enabled if the proxy is authorized to use the roles on behalf of the client.
         * 
         * @return builder
         * 
         */
        public Builder roles(String... roles) {
            return roles(List.of(roles));
        }

        /**
         * @param userName (Updatable) The user name.
         * 
         * @return builder
         * 
         */
        public Builder userName(@Nullable Output<String> userName) {
            $.userName = userName;
            return this;
        }

        /**
         * @param userName (Updatable) The user name.
         * 
         * @return builder
         * 
         */
        public Builder userName(String userName) {
            return userName(Output.of(userName));
        }

        /**
         * @param userPassword (Updatable) The user password.
         * 
         * @return builder
         * 
         */
        public Builder userPassword(@Nullable Output<DatabaseToolsConnectionProxyClientUserPasswordArgs> userPassword) {
            $.userPassword = userPassword;
            return this;
        }

        /**
         * @param userPassword (Updatable) The user password.
         * 
         * @return builder
         * 
         */
        public Builder userPassword(DatabaseToolsConnectionProxyClientUserPasswordArgs userPassword) {
            return userPassword(Output.of(userPassword));
        }

        public DatabaseToolsConnectionProxyClientArgs build() {
            if ($.proxyAuthenticationType == null) {
                throw new MissingRequiredPropertyException("DatabaseToolsConnectionProxyClientArgs", "proxyAuthenticationType");
            }
            return $;
        }
    }

}
