// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseManagement.inputs.ManagedDatabasesResetDatabaseParameterCredentialsArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;


public final class ManagedDatabasesResetDatabaseParameterArgs extends com.pulumi.resources.ResourceArgs {

    public static final ManagedDatabasesResetDatabaseParameterArgs Empty = new ManagedDatabasesResetDatabaseParameterArgs();

    /**
     * The database credentials used to perform management activity.
     * 
     */
    @Import(name="credentials", required=true)
    private Output<ManagedDatabasesResetDatabaseParameterCredentialsArgs> credentials;

    /**
     * @return The database credentials used to perform management activity.
     * 
     */
    public Output<ManagedDatabasesResetDatabaseParameterCredentialsArgs> credentials() {
        return this.credentials;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    @Import(name="managedDatabaseId", required=true)
    private Output<String> managedDatabaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    public Output<String> managedDatabaseId() {
        return this.managedDatabaseId;
    }

    /**
     * A list of database parameter names.
     * 
     */
    @Import(name="parameters", required=true)
    private Output<List<String>> parameters;

    /**
     * @return A list of database parameter names.
     * 
     */
    public Output<List<String>> parameters() {
        return this.parameters;
    }

    /**
     * The clause used to specify when the parameter change takes effect.
     * 
     */
    @Import(name="scope", required=true)
    private Output<String> scope;

    /**
     * @return The clause used to specify when the parameter change takes effect.
     * 
     */
    public Output<String> scope() {
        return this.scope;
    }

    private ManagedDatabasesResetDatabaseParameterArgs() {}

    private ManagedDatabasesResetDatabaseParameterArgs(ManagedDatabasesResetDatabaseParameterArgs $) {
        this.credentials = $.credentials;
        this.managedDatabaseId = $.managedDatabaseId;
        this.parameters = $.parameters;
        this.scope = $.scope;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ManagedDatabasesResetDatabaseParameterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ManagedDatabasesResetDatabaseParameterArgs $;

        public Builder() {
            $ = new ManagedDatabasesResetDatabaseParameterArgs();
        }

        public Builder(ManagedDatabasesResetDatabaseParameterArgs defaults) {
            $ = new ManagedDatabasesResetDatabaseParameterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param credentials The database credentials used to perform management activity.
         * 
         * @return builder
         * 
         */
        public Builder credentials(Output<ManagedDatabasesResetDatabaseParameterCredentialsArgs> credentials) {
            $.credentials = credentials;
            return this;
        }

        /**
         * @param credentials The database credentials used to perform management activity.
         * 
         * @return builder
         * 
         */
        public Builder credentials(ManagedDatabasesResetDatabaseParameterCredentialsArgs credentials) {
            return credentials(Output.of(credentials));
        }

        /**
         * @param managedDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseId(Output<String> managedDatabaseId) {
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
        public Builder parameters(Output<List<String>> parameters) {
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
         * @return builder
         * 
         */
        public Builder scope(Output<String> scope) {
            $.scope = scope;
            return this;
        }

        /**
         * @param scope The clause used to specify when the parameter change takes effect.
         * 
         * @return builder
         * 
         */
        public Builder scope(String scope) {
            return scope(Output.of(scope));
        }

        public ManagedDatabasesResetDatabaseParameterArgs build() {
            $.credentials = Objects.requireNonNull($.credentials, "expected parameter 'credentials' to be non-null");
            $.managedDatabaseId = Objects.requireNonNull($.managedDatabaseId, "expected parameter 'managedDatabaseId' to be non-null");
            $.parameters = Objects.requireNonNull($.parameters, "expected parameter 'parameters' to be non-null");
            $.scope = Objects.requireNonNull($.scope, "expected parameter 'scope' to be non-null");
            return $;
        }
    }

}