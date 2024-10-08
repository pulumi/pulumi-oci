// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMysqlBackupsBackupSourceDetail {
    /**
     * @return Backup OCID
     * 
     */
    private String backupId;
    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String compartmentId;
    /**
     * @return The region identifier of the region where the DB system exists. For more information, please see [Regions and Availability Domains](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm).
     * 
     */
    private String region;

    private GetMysqlBackupsBackupSourceDetail() {}
    /**
     * @return Backup OCID
     * 
     */
    public String backupId() {
        return this.backupId;
    }
    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The region identifier of the region where the DB system exists. For more information, please see [Regions and Availability Domains](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm).
     * 
     */
    public String region() {
        return this.region;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMysqlBackupsBackupSourceDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String backupId;
        private String compartmentId;
        private String region;
        public Builder() {}
        public Builder(GetMysqlBackupsBackupSourceDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backupId = defaults.backupId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.region = defaults.region;
        }

        @CustomType.Setter
        public Builder backupId(String backupId) {
            if (backupId == null) {
              throw new MissingRequiredPropertyException("GetMysqlBackupsBackupSourceDetail", "backupId");
            }
            this.backupId = backupId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetMysqlBackupsBackupSourceDetail", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder region(String region) {
            if (region == null) {
              throw new MissingRequiredPropertyException("GetMysqlBackupsBackupSourceDetail", "region");
            }
            this.region = region;
            return this;
        }
        public GetMysqlBackupsBackupSourceDetail build() {
            final var _resultValue = new GetMysqlBackupsBackupSourceDetail();
            _resultValue.backupId = backupId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.region = region;
            return _resultValue;
        }
    }
}
