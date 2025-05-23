// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseManagement.inputs.ManagedDatabasesResetDatabaseParameterCredentialsArgs;
import com.pulumi.oci.DatabaseManagement.inputs.ManagedDatabasesResetDatabaseParameterDatabaseCredentialArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ManagedDatabasesResetDatabaseParameterState extends com.pulumi.resources.ResourceArgs {

    public static final ManagedDatabasesResetDatabaseParameterState Empty = new ManagedDatabasesResetDatabaseParameterState();

    /**
     * The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
     * 
     */
    @Import(name="credentials")
    private @Nullable Output<ManagedDatabasesResetDatabaseParameterCredentialsArgs> credentials;

    /**
     * @return The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
     * 
     */
    public Optional<Output<ManagedDatabasesResetDatabaseParameterCredentialsArgs>> credentials() {
        return Optional.ofNullable(this.credentials);
    }

    /**
     * The credential to connect to the database to perform tablespace administration tasks.
     * 
     */
    @Import(name="databaseCredential")
    private @Nullable Output<ManagedDatabasesResetDatabaseParameterDatabaseCredentialArgs> databaseCredential;

    /**
     * @return The credential to connect to the database to perform tablespace administration tasks.
     * 
     */
    public Optional<Output<ManagedDatabasesResetDatabaseParameterDatabaseCredentialArgs>> databaseCredential() {
        return Optional.ofNullable(this.databaseCredential);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    @Import(name="managedDatabaseId")
    private @Nullable Output<String> managedDatabaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    public Optional<Output<String>> managedDatabaseId() {
        return Optional.ofNullable(this.managedDatabaseId);
    }

    /**
     * A list of database parameter names.
     * 
     */
    @Import(name="parameters")
    private @Nullable Output<List<String>> parameters;

    /**
     * @return A list of database parameter names.
     * 
     */
    public Optional<Output<List<String>>> parameters() {
        return Optional.ofNullable(this.parameters);
    }

    /**
     * The clause used to specify when the parameter change takes effect.
     * 
     * Use `MEMORY` to make the change in memory and ensure that it takes effect immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="scope")
    private @Nullable Output<String> scope;

    /**
     * @return The clause used to specify when the parameter change takes effect.
     * 
     * Use `MEMORY` to make the change in memory and ensure that it takes effect immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> scope() {
        return Optional.ofNullable(this.scope);
    }

    private ManagedDatabasesResetDatabaseParameterState() {}

    private ManagedDatabasesResetDatabaseParameterState(ManagedDatabasesResetDatabaseParameterState $) {
        this.credentials = $.credentials;
        this.databaseCredential = $.databaseCredential;
        this.managedDatabaseId = $.managedDatabaseId;
        this.parameters = $.parameters;
        this.scope = $.scope;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ManagedDatabasesResetDatabaseParameterState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ManagedDatabasesResetDatabaseParameterState $;

        public Builder() {
            $ = new ManagedDatabasesResetDatabaseParameterState();
        }

        public Builder(ManagedDatabasesResetDatabaseParameterState defaults) {
            $ = new ManagedDatabasesResetDatabaseParameterState(Objects.requireNonNull(defaults));
        }

        /**
         * @param credentials The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
         * 
         * @return builder
         * 
         */
        public Builder credentials(@Nullable Output<ManagedDatabasesResetDatabaseParameterCredentialsArgs> credentials) {
            $.credentials = credentials;
            return this;
        }

        /**
         * @param credentials The database credentials used to perform management activity. Provide one of the following attribute set. (userName, password, role) OR (userName, secretId, role) OR (namedCredentialId)
         * 
         * @return builder
         * 
         */
        public Builder credentials(ManagedDatabasesResetDatabaseParameterCredentialsArgs credentials) {
            return credentials(Output.of(credentials));
        }

        /**
         * @param databaseCredential The credential to connect to the database to perform tablespace administration tasks.
         * 
         * @return builder
         * 
         */
        public Builder databaseCredential(@Nullable Output<ManagedDatabasesResetDatabaseParameterDatabaseCredentialArgs> databaseCredential) {
            $.databaseCredential = databaseCredential;
            return this;
        }

        /**
         * @param databaseCredential The credential to connect to the database to perform tablespace administration tasks.
         * 
         * @return builder
         * 
         */
        public Builder databaseCredential(ManagedDatabasesResetDatabaseParameterDatabaseCredentialArgs databaseCredential) {
            return databaseCredential(Output.of(databaseCredential));
        }

        /**
         * @param managedDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseId(@Nullable Output<String> managedDatabaseId) {
            $.managedDatabaseId = managedDatabaseId;
            return this;
        }

        /**
         * @param managedDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseId(String managedDatabaseId) {
            return managedDatabaseId(Output.of(managedDatabaseId));
        }

        /**
         * @param parameters A list of database parameter names.
         * 
         * @return builder
         * 
         */
        public Builder parameters(@Nullable Output<List<String>> parameters) {
            $.parameters = parameters;
            return this;
        }

        /**
         * @param parameters A list of database parameter names.
         * 
         * @return builder
         * 
         */
        public Builder parameters(List<String> parameters) {
            return parameters(Output.of(parameters));
        }

        /**
         * @param parameters A list of database parameter names.
         * 
         * @return builder
         * 
         */
        public Builder parameters(String... parameters) {
            return parameters(List.of(parameters));
        }

        /**
         * @param scope The clause used to specify when the parameter change takes effect.
         * 
         * Use `MEMORY` to make the change in memory and ensure that it takes effect immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder scope(@Nullable Output<String> scope) {
            $.scope = scope;
            return this;
        }

        /**
         * @param scope The clause used to specify when the parameter change takes effect.
         * 
         * Use `MEMORY` to make the change in memory and ensure that it takes effect immediately. Use `SPFILE` to make the change in the server parameter file. The change takes effect when the database is next shut down and started up again. Use `BOTH` to make the change in memory and in the server parameter file. The change takes effect immediately and persists after the database is shut down and started up again.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder scope(String scope) {
            return scope(Output.of(scope));
        }

        public ManagedDatabasesResetDatabaseParameterState build() {
            return $;
        }
    }

}
