// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MysqlDbSystemSource {
    /**
     * @return The OCID of the backup to be used as the source for the new DB System.
     * 
     */
    private @Nullable String backupId;
    /**
     * @return The OCID of the DB System from which a backup shall be selected to be restored when creating the new DB System. Use this together with recovery point to perform a point in time recovery operation.
     * 
     */
    private @Nullable String dbSystemId;
    /**
     * @return The date and time, as per RFC 3339, of the change up to which the new DB System shall be restored to, using a backup and logs from the original DB System. In case no point in time is specified, then this new DB System shall be restored up to the latest change recorded for the original DB System.
     * 
     */
    private @Nullable String recoveryPoint;
    /**
     * @return The specific source identifier. Use `BACKUP` for creating a new database by restoring from a backup.
     * 
     */
    private String sourceType;

    private MysqlDbSystemSource() {}
    /**
     * @return The OCID of the backup to be used as the source for the new DB System.
     * 
     */
    public Optional<String> backupId() {
        return Optional.ofNullable(this.backupId);
    }
    /**
     * @return The OCID of the DB System from which a backup shall be selected to be restored when creating the new DB System. Use this together with recovery point to perform a point in time recovery operation.
     * 
     */
    public Optional<String> dbSystemId() {
        return Optional.ofNullable(this.dbSystemId);
    }
    /**
     * @return The date and time, as per RFC 3339, of the change up to which the new DB System shall be restored to, using a backup and logs from the original DB System. In case no point in time is specified, then this new DB System shall be restored up to the latest change recorded for the original DB System.
     * 
     */
    public Optional<String> recoveryPoint() {
        return Optional.ofNullable(this.recoveryPoint);
    }
    /**
     * @return The specific source identifier. Use `BACKUP` for creating a new database by restoring from a backup.
     * 
     */
    public String sourceType() {
        return this.sourceType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MysqlDbSystemSource defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String backupId;
        private @Nullable String dbSystemId;
        private @Nullable String recoveryPoint;
        private String sourceType;
        public Builder() {}
        public Builder(MysqlDbSystemSource defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backupId = defaults.backupId;
    	      this.dbSystemId = defaults.dbSystemId;
    	      this.recoveryPoint = defaults.recoveryPoint;
    	      this.sourceType = defaults.sourceType;
        }

        @CustomType.Setter
        public Builder backupId(@Nullable String backupId) {
            this.backupId = backupId;
            return this;
        }
        @CustomType.Setter
        public Builder dbSystemId(@Nullable String dbSystemId) {
            this.dbSystemId = dbSystemId;
            return this;
        }
        @CustomType.Setter
        public Builder recoveryPoint(@Nullable String recoveryPoint) {
            this.recoveryPoint = recoveryPoint;
            return this;
        }
        @CustomType.Setter
        public Builder sourceType(String sourceType) {
            this.sourceType = Objects.requireNonNull(sourceType);
            return this;
        }
        public MysqlDbSystemSource build() {
            final var o = new MysqlDbSystemSource();
            o.backupId = backupId;
            o.dbSystemId = dbSystemId;
            o.recoveryPoint = recoveryPoint;
            o.sourceType = sourceType;
            return o;
        }
    }
}