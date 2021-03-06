// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationDataTransferMediumDetailDatabaseLinkDetail;
import com.pulumi.oci.DatabaseMigration.outputs.GetMigrationDataTransferMediumDetailObjectStorageDetail;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetMigrationDataTransferMediumDetail {
    /**
     * @return Optional details for creating a network database link from Oracle Cloud Infrastructure database to on-premise database.
     * 
     */
    private final List<GetMigrationDataTransferMediumDetailDatabaseLinkDetail> databaseLinkDetails;
    /**
     * @return In lieu of a network database link, Oracle Cloud Infrastructure Object Storage bucket will be used to store Data Pump dump files for the migration. Additionally, it can be specified alongside a database link data transfer medium.
     * 
     */
    private final List<GetMigrationDataTransferMediumDetailObjectStorageDetail> objectStorageDetails;

    @CustomType.Constructor
    private GetMigrationDataTransferMediumDetail(
        @CustomType.Parameter("databaseLinkDetails") List<GetMigrationDataTransferMediumDetailDatabaseLinkDetail> databaseLinkDetails,
        @CustomType.Parameter("objectStorageDetails") List<GetMigrationDataTransferMediumDetailObjectStorageDetail> objectStorageDetails) {
        this.databaseLinkDetails = databaseLinkDetails;
        this.objectStorageDetails = objectStorageDetails;
    }

    /**
     * @return Optional details for creating a network database link from Oracle Cloud Infrastructure database to on-premise database.
     * 
     */
    public List<GetMigrationDataTransferMediumDetailDatabaseLinkDetail> databaseLinkDetails() {
        return this.databaseLinkDetails;
    }
    /**
     * @return In lieu of a network database link, Oracle Cloud Infrastructure Object Storage bucket will be used to store Data Pump dump files for the migration. Additionally, it can be specified alongside a database link data transfer medium.
     * 
     */
    public List<GetMigrationDataTransferMediumDetailObjectStorageDetail> objectStorageDetails() {
        return this.objectStorageDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMigrationDataTransferMediumDetail defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetMigrationDataTransferMediumDetailDatabaseLinkDetail> databaseLinkDetails;
        private List<GetMigrationDataTransferMediumDetailObjectStorageDetail> objectStorageDetails;

        public Builder() {
    	      // Empty
        }

        public Builder(GetMigrationDataTransferMediumDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.databaseLinkDetails = defaults.databaseLinkDetails;
    	      this.objectStorageDetails = defaults.objectStorageDetails;
        }

        public Builder databaseLinkDetails(List<GetMigrationDataTransferMediumDetailDatabaseLinkDetail> databaseLinkDetails) {
            this.databaseLinkDetails = Objects.requireNonNull(databaseLinkDetails);
            return this;
        }
        public Builder databaseLinkDetails(GetMigrationDataTransferMediumDetailDatabaseLinkDetail... databaseLinkDetails) {
            return databaseLinkDetails(List.of(databaseLinkDetails));
        }
        public Builder objectStorageDetails(List<GetMigrationDataTransferMediumDetailObjectStorageDetail> objectStorageDetails) {
            this.objectStorageDetails = Objects.requireNonNull(objectStorageDetails);
            return this;
        }
        public Builder objectStorageDetails(GetMigrationDataTransferMediumDetailObjectStorageDetail... objectStorageDetails) {
            return objectStorageDetails(List.of(objectStorageDetails));
        }        public GetMigrationDataTransferMediumDetail build() {
            return new GetMigrationDataTransferMediumDetail(databaseLinkDetails, objectStorageDetails);
        }
    }
}
