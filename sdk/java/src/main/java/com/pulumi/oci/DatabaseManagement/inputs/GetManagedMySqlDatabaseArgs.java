// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetManagedMySqlDatabaseArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedMySqlDatabaseArgs Empty = new GetManagedMySqlDatabaseArgs();

    /**
     * The OCID of ManagedMySqlDatabase.
     * 
     */
    @Import(name="managedMySqlDatabaseId", required=true)
    private Output<String> managedMySqlDatabaseId;

    /**
     * @return The OCID of ManagedMySqlDatabase.
     * 
     */
    public Output<String> managedMySqlDatabaseId() {
        return this.managedMySqlDatabaseId;
    }

    private GetManagedMySqlDatabaseArgs() {}

    private GetManagedMySqlDatabaseArgs(GetManagedMySqlDatabaseArgs $) {
        this.managedMySqlDatabaseId = $.managedMySqlDatabaseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedMySqlDatabaseArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedMySqlDatabaseArgs $;

        public Builder() {
            $ = new GetManagedMySqlDatabaseArgs();
        }

        public Builder(GetManagedMySqlDatabaseArgs defaults) {
            $ = new GetManagedMySqlDatabaseArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param managedMySqlDatabaseId The OCID of ManagedMySqlDatabase.
         * 
         * @return builder
         * 
         */
        public Builder managedMySqlDatabaseId(Output<String> managedMySqlDatabaseId) {
            $.managedMySqlDatabaseId = managedMySqlDatabaseId;
            return this;
        }

        /**
         * @param managedMySqlDatabaseId The OCID of ManagedMySqlDatabase.
         * 
         * @return builder
         * 
         */
        public Builder managedMySqlDatabaseId(String managedMySqlDatabaseId) {
            return managedMySqlDatabaseId(Output.of(managedMySqlDatabaseId));
        }

        public GetManagedMySqlDatabaseArgs build() {
            $.managedMySqlDatabaseId = Objects.requireNonNull($.managedMySqlDatabaseId, "expected parameter 'managedMySqlDatabaseId' to be non-null");
            return $;
        }
    }

}