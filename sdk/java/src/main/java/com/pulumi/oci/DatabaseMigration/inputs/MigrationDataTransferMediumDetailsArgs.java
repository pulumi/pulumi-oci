// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationDataTransferMediumDetailsDatabaseLinkDetailsArgs;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationDataTransferMediumDetailsObjectStorageDetailsArgs;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MigrationDataTransferMediumDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final MigrationDataTransferMediumDetailsArgs Empty = new MigrationDataTransferMediumDetailsArgs();

    /**
     * (Updatable) Optional details for creating a network database link from Oracle Cloud Infrastructure database to on-premise database.
     * 
     */
    @Import(name="databaseLinkDetails")
    private @Nullable Output<MigrationDataTransferMediumDetailsDatabaseLinkDetailsArgs> databaseLinkDetails;

    /**
     * @return (Updatable) Optional details for creating a network database link from Oracle Cloud Infrastructure database to on-premise database.
     * 
     */
    public Optional<Output<MigrationDataTransferMediumDetailsDatabaseLinkDetailsArgs>> databaseLinkDetails() {
        return Optional.ofNullable(this.databaseLinkDetails);
    }

    /**
     * (Updatable) In lieu of a network database link, Oracle Cloud Infrastructure Object Storage bucket will be used to store Data Pump dump files for the migration. Additionally, it can be specified alongside a database link data transfer medium.
     * 
     */
    @Import(name="objectStorageDetails")
    private @Nullable Output<MigrationDataTransferMediumDetailsObjectStorageDetailsArgs> objectStorageDetails;

    /**
     * @return (Updatable) In lieu of a network database link, Oracle Cloud Infrastructure Object Storage bucket will be used to store Data Pump dump files for the migration. Additionally, it can be specified alongside a database link data transfer medium.
     * 
     */
    public Optional<Output<MigrationDataTransferMediumDetailsObjectStorageDetailsArgs>> objectStorageDetails() {
        return Optional.ofNullable(this.objectStorageDetails);
    }

    private MigrationDataTransferMediumDetailsArgs() {}

    private MigrationDataTransferMediumDetailsArgs(MigrationDataTransferMediumDetailsArgs $) {
        this.databaseLinkDetails = $.databaseLinkDetails;
        this.objectStorageDetails = $.objectStorageDetails;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MigrationDataTransferMediumDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MigrationDataTransferMediumDetailsArgs $;

        public Builder() {
            $ = new MigrationDataTransferMediumDetailsArgs();
        }

        public Builder(MigrationDataTransferMediumDetailsArgs defaults) {
            $ = new MigrationDataTransferMediumDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param databaseLinkDetails (Updatable) Optional details for creating a network database link from Oracle Cloud Infrastructure database to on-premise database.
         * 
         * @return builder
         * 
         */
        public Builder databaseLinkDetails(@Nullable Output<MigrationDataTransferMediumDetailsDatabaseLinkDetailsArgs> databaseLinkDetails) {
            $.databaseLinkDetails = databaseLinkDetails;
            return this;
        }

        /**
         * @param databaseLinkDetails (Updatable) Optional details for creating a network database link from Oracle Cloud Infrastructure database to on-premise database.
         * 
         * @return builder
         * 
         */
        public Builder databaseLinkDetails(MigrationDataTransferMediumDetailsDatabaseLinkDetailsArgs databaseLinkDetails) {
            return databaseLinkDetails(Output.of(databaseLinkDetails));
        }

        /**
         * @param objectStorageDetails (Updatable) In lieu of a network database link, Oracle Cloud Infrastructure Object Storage bucket will be used to store Data Pump dump files for the migration. Additionally, it can be specified alongside a database link data transfer medium.
         * 
         * @return builder
         * 
         */
        public Builder objectStorageDetails(@Nullable Output<MigrationDataTransferMediumDetailsObjectStorageDetailsArgs> objectStorageDetails) {
            $.objectStorageDetails = objectStorageDetails;
            return this;
        }

        /**
         * @param objectStorageDetails (Updatable) In lieu of a network database link, Oracle Cloud Infrastructure Object Storage bucket will be used to store Data Pump dump files for the migration. Additionally, it can be specified alongside a database link data transfer medium.
         * 
         * @return builder
         * 
         */
        public Builder objectStorageDetails(MigrationDataTransferMediumDetailsObjectStorageDetailsArgs objectStorageDetails) {
            return objectStorageDetails(Output.of(objectStorageDetails));
        }

        public MigrationDataTransferMediumDetailsArgs build() {
            return $;
        }
    }

}