// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DatabaseDatabaseDbBackupConfigBackupDestinationDetailArgs extends com.pulumi.resources.ResourceArgs {

    public static final DatabaseDatabaseDbBackupConfigBackupDestinationDetailArgs Empty = new DatabaseDatabaseDbBackupConfigBackupDestinationDetailArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * Type of the database backup destination.
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return Type of the database backup destination.
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    @Import(name="vpcUser")
    private @Nullable Output<String> vpcUser;

    public Optional<Output<String>> vpcUser() {
        return Optional.ofNullable(this.vpcUser);
    }

    private DatabaseDatabaseDbBackupConfigBackupDestinationDetailArgs() {}

    private DatabaseDatabaseDbBackupConfigBackupDestinationDetailArgs(DatabaseDatabaseDbBackupConfigBackupDestinationDetailArgs $) {
        this.id = $.id;
        this.type = $.type;
        this.vpcUser = $.vpcUser;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DatabaseDatabaseDbBackupConfigBackupDestinationDetailArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DatabaseDatabaseDbBackupConfigBackupDestinationDetailArgs $;

        public Builder() {
            $ = new DatabaseDatabaseDbBackupConfigBackupDestinationDetailArgs();
        }

        public Builder(DatabaseDatabaseDbBackupConfigBackupDestinationDetailArgs defaults) {
            $ = new DatabaseDatabaseDbBackupConfigBackupDestinationDetailArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param id The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param type Type of the database backup destination.
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type Type of the database backup destination.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public Builder vpcUser(@Nullable Output<String> vpcUser) {
            $.vpcUser = vpcUser;
            return this;
        }

        public Builder vpcUser(String vpcUser) {
            return vpcUser(Output.of(vpcUser));
        }

        public DatabaseDatabaseDbBackupConfigBackupDestinationDetailArgs build() {
            return $;
        }
    }

}