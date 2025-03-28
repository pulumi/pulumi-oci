// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.util.Objects;

@CustomType
public final class GetMysqlBackupsBackupDbSystemSnapshotBackupPolicyPitrPolicy {
    /**
     * @return Specifies if the DB System read endpoint is enabled or not.
     * 
     */
    private Boolean isEnabled;

    private GetMysqlBackupsBackupDbSystemSnapshotBackupPolicyPitrPolicy() {}
    /**
     * @return Specifies if the DB System read endpoint is enabled or not.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMysqlBackupsBackupDbSystemSnapshotBackupPolicyPitrPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean isEnabled;
        public Builder() {}
        public Builder(GetMysqlBackupsBackupDbSystemSnapshotBackupPolicyPitrPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isEnabled = defaults.isEnabled;
        }

        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            if (isEnabled == null) {
              throw new MissingRequiredPropertyException("GetMysqlBackupsBackupDbSystemSnapshotBackupPolicyPitrPolicy", "isEnabled");
            }
            this.isEnabled = isEnabled;
            return this;
        }
        public GetMysqlBackupsBackupDbSystemSnapshotBackupPolicyPitrPolicy build() {
            final var _resultValue = new GetMysqlBackupsBackupDbSystemSnapshotBackupPolicyPitrPolicy();
            _resultValue.isEnabled = isEnabled;
            return _resultValue;
        }
    }
}
