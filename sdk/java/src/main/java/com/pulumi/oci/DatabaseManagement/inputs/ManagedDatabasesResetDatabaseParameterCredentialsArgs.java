// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ManagedDatabasesResetDatabaseParameterCredentialsArgs extends com.pulumi.resources.ResourceArgs {

    public static final ManagedDatabasesResetDatabaseParameterCredentialsArgs Empty = new ManagedDatabasesResetDatabaseParameterCredentialsArgs();

    /**
     * The password for the database user name.
     * 
     */
    @Import(name="password")
    private @Nullable Output<String> password;

    /**
     * @return The password for the database user name.
     * 
     */
    public Optional<Output<String>> password() {
        return Optional.ofNullable(this.password);
    }

    /**
     * The role of the database user. Indicates whether the database user is a normal user or sysdba.
     * 
     */
    @Import(name="role")
    private @Nullable Output<String> role;

    /**
     * @return The role of the database user. Indicates whether the database user is a normal user or sysdba.
     * 
     */
    public Optional<Output<String>> role() {
        return Optional.ofNullable(this.role);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the user password.
     * 
     */
    @Import(name="secretId")
    private @Nullable Output<String> secretId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the user password.
     * 
     */
    public Optional<Output<String>> secretId() {
        return Optional.ofNullable(this.secretId);
    }

    /**
     * The database user name used to perform management activity.
     * 
     */
    @Import(name="userName")
    private @Nullable Output<String> userName;

    /**
     * @return The database user name used to perform management activity.
     * 
     */
    public Optional<Output<String>> userName() {
        return Optional.ofNullable(this.userName);
    }

    private ManagedDatabasesResetDatabaseParameterCredentialsArgs() {}

    private ManagedDatabasesResetDatabaseParameterCredentialsArgs(ManagedDatabasesResetDatabaseParameterCredentialsArgs $) {
        this.password = $.password;
        this.role = $.role;
        this.secretId = $.secretId;
        this.userName = $.userName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ManagedDatabasesResetDatabaseParameterCredentialsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ManagedDatabasesResetDatabaseParameterCredentialsArgs $;

        public Builder() {
            $ = new ManagedDatabasesResetDatabaseParameterCredentialsArgs();
        }

        public Builder(ManagedDatabasesResetDatabaseParameterCredentialsArgs defaults) {
            $ = new ManagedDatabasesResetDatabaseParameterCredentialsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param password The password for the database user name.
         * 
         * @return builder
         * 
         */
        public Builder password(@Nullable Output<String> password) {
            $.password = password;
            return this;
        }

        /**
         * @param password The password for the database user name.
         * 
         * @return builder
         * 
         */
        public Builder password(String password) {
            return password(Output.of(password));
        }

        /**
         * @param role The role of the database user. Indicates whether the database user is a normal user or sysdba.
         * 
         * @return builder
         * 
         */
        public Builder role(@Nullable Output<String> role) {
            $.role = role;
            return this;
        }

        /**
         * @param role The role of the database user. Indicates whether the database user is a normal user or sysdba.
         * 
         * @return builder
         * 
         */
        public Builder role(String role) {
            return role(Output.of(role));
        }

        /**
         * @param secretId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the user password.
         * 
         * @return builder
         * 
         */
        public Builder secretId(@Nullable Output<String> secretId) {
            $.secretId = secretId;
            return this;
        }

        /**
         * @param secretId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the user password.
         * 
         * @return builder
         * 
         */
        public Builder secretId(String secretId) {
            return secretId(Output.of(secretId));
        }

        /**
         * @param userName The database user name used to perform management activity.
         * 
         * @return builder
         * 
         */
        public Builder userName(@Nullable Output<String> userName) {
            $.userName = userName;
            return this;
        }

        /**
         * @param userName The database user name used to perform management activity.
         * 
         * @return builder
         * 
         */
        public Builder userName(String userName) {
            return userName(Output.of(userName));
        }

        public ManagedDatabasesResetDatabaseParameterCredentialsArgs build() {
            return $;
        }
    }

}