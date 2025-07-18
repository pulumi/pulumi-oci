// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetManagedMySqlDatabaseBinaryLogInformationArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedMySqlDatabaseBinaryLogInformationArgs Empty = new GetManagedMySqlDatabaseBinaryLogInformationArgs();

    /**
     * The OCID of the Managed MySQL Database.
     * 
     */
    @Import(name="managedMySqlDatabaseId", required=true)
    private Output<String> managedMySqlDatabaseId;

    /**
     * @return The OCID of the Managed MySQL Database.
     * 
     */
    public Output<String> managedMySqlDatabaseId() {
        return this.managedMySqlDatabaseId;
    }

    private GetManagedMySqlDatabaseBinaryLogInformationArgs() {}

    private GetManagedMySqlDatabaseBinaryLogInformationArgs(GetManagedMySqlDatabaseBinaryLogInformationArgs $) {
        this.managedMySqlDatabaseId = $.managedMySqlDatabaseId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedMySqlDatabaseBinaryLogInformationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedMySqlDatabaseBinaryLogInformationArgs $;

        public Builder() {
            $ = new GetManagedMySqlDatabaseBinaryLogInformationArgs();
        }

        public Builder(GetManagedMySqlDatabaseBinaryLogInformationArgs defaults) {
            $ = new GetManagedMySqlDatabaseBinaryLogInformationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param managedMySqlDatabaseId The OCID of the Managed MySQL Database.
         * 
         * @return builder
         * 
         */
        public Builder managedMySqlDatabaseId(Output<String> managedMySqlDatabaseId) {
            $.managedMySqlDatabaseId = managedMySqlDatabaseId;
            return this;
        }

        /**
         * @param managedMySqlDatabaseId The OCID of the Managed MySQL Database.
         * 
         * @return builder
         * 
         */
        public Builder managedMySqlDatabaseId(String managedMySqlDatabaseId) {
            return managedMySqlDatabaseId(Output.of(managedMySqlDatabaseId));
        }

        public GetManagedMySqlDatabaseBinaryLogInformationArgs build() {
            if ($.managedMySqlDatabaseId == null) {
                throw new MissingRequiredPropertyException("GetManagedMySqlDatabaseBinaryLogInformationArgs", "managedMySqlDatabaseId");
            }
            return $;
        }
    }

}
