// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMysqlDbSystemsDbSystemSource {
    /**
     * @return The OCID of the backup to be used as the source for the new DB System.
     * 
     */
    private String backupId;
    /**
     * @return The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String dbSystemId;
    /**
     * @return The date and time, as per RFC 3339, of the change up to which the new DB System shall be restored to, using a backup and logs from the original DB System. In case no point in time is specified, then this new DB System shall be restored up to the latest change recorded for the original DB System.
     * 
     */
    private String recoveryPoint;
    /**
     * @return The specific source identifier.
     * 
     */
    private String sourceType;
    private String sourceUrl;

    private GetMysqlDbSystemsDbSystemSource() {}
    /**
     * @return The OCID of the backup to be used as the source for the new DB System.
     * 
     */
    public String backupId() {
        return this.backupId;
    }
    /**
     * @return The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String dbSystemId() {
        return this.dbSystemId;
    }
    /**
     * @return The date and time, as per RFC 3339, of the change up to which the new DB System shall be restored to, using a backup and logs from the original DB System. In case no point in time is specified, then this new DB System shall be restored up to the latest change recorded for the original DB System.
     * 
     */
    public String recoveryPoint() {
        return this.recoveryPoint;
    }
    /**
     * @return The specific source identifier.
     * 
     */
    public String sourceType() {
        return this.sourceType;
    }
    public String sourceUrl() {
        return this.sourceUrl;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMysqlDbSystemsDbSystemSource defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String backupId;
        private String dbSystemId;
        private String recoveryPoint;
        private String sourceType;
        private String sourceUrl;
        public Builder() {}
        public Builder(GetMysqlDbSystemsDbSystemSource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backupId = defaults.backupId;
    	      this.dbSystemId = defaults.dbSystemId;
    	      this.recoveryPoint = defaults.recoveryPoint;
    	      this.sourceType = defaults.sourceType;
    	      this.sourceUrl = defaults.sourceUrl;
        }

        @CustomType.Setter
        public Builder backupId(String backupId) {
            if (backupId == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemsDbSystemSource", "backupId");
            }
            this.backupId = backupId;
            return this;
        }
        @CustomType.Setter
        public Builder dbSystemId(String dbSystemId) {
            if (dbSystemId == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemsDbSystemSource", "dbSystemId");
            }
            this.dbSystemId = dbSystemId;
            return this;
        }
        @CustomType.Setter
        public Builder recoveryPoint(String recoveryPoint) {
            if (recoveryPoint == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemsDbSystemSource", "recoveryPoint");
            }
            this.recoveryPoint = recoveryPoint;
            return this;
        }
        @CustomType.Setter
        public Builder sourceType(String sourceType) {
            if (sourceType == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemsDbSystemSource", "sourceType");
            }
            this.sourceType = sourceType;
            return this;
        }
        @CustomType.Setter
        public Builder sourceUrl(String sourceUrl) {
            if (sourceUrl == null) {
              throw new MissingRequiredPropertyException("GetMysqlDbSystemsDbSystemSource", "sourceUrl");
            }
            this.sourceUrl = sourceUrl;
            return this;
        }
        public GetMysqlDbSystemsDbSystemSource build() {
            final var _resultValue = new GetMysqlDbSystemsDbSystemSource();
            _resultValue.backupId = backupId;
            _resultValue.dbSystemId = dbSystemId;
            _resultValue.recoveryPoint = recoveryPoint;
            _resultValue.sourceType = sourceType;
            _resultValue.sourceUrl = sourceUrl;
            return _resultValue;
        }
    }
}
