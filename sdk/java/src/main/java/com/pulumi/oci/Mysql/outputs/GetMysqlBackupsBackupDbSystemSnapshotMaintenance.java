// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetMysqlBackupsBackupDbSystemSnapshotMaintenance {
    /**
     * @return The start time of the maintenance window.
     * 
     */
    private String windowStartTime;

    private GetMysqlBackupsBackupDbSystemSnapshotMaintenance() {}
    /**
     * @return The start time of the maintenance window.
     * 
     */
    public String windowStartTime() {
        return this.windowStartTime;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMysqlBackupsBackupDbSystemSnapshotMaintenance defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String windowStartTime;
        public Builder() {}
        public Builder(GetMysqlBackupsBackupDbSystemSnapshotMaintenance defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.windowStartTime = defaults.windowStartTime;
        }

        @CustomType.Setter
        public Builder windowStartTime(String windowStartTime) {
            if (windowStartTime == null) {
              throw new MissingRequiredPropertyException("GetMysqlBackupsBackupDbSystemSnapshotMaintenance", "windowStartTime");
            }
            this.windowStartTime = windowStartTime;
            return this;
        }
        public GetMysqlBackupsBackupDbSystemSnapshotMaintenance build() {
            final var _resultValue = new GetMysqlBackupsBackupDbSystemSnapshotMaintenance();
            _resultValue.windowStartTime = windowStartTime;
            return _resultValue;
        }
    }
}
