// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;

@CustomType
public final class GetMysqlBackupDbSystemSnapshotBackupPolicyPitrPolicy {
    /**
     * @return Specifies if PITR is enabled or disabled.
     * 
     */
    private Boolean isEnabled;

    private GetMysqlBackupDbSystemSnapshotBackupPolicyPitrPolicy() {}
    /**
     * @return Specifies if PITR is enabled or disabled.
     * 
     */
    public Boolean isEnabled() {
        return this.isEnabled;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMysqlBackupDbSystemSnapshotBackupPolicyPitrPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean isEnabled;
        public Builder() {}
        public Builder(GetMysqlBackupDbSystemSnapshotBackupPolicyPitrPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isEnabled = defaults.isEnabled;
        }

        @CustomType.Setter
        public Builder isEnabled(Boolean isEnabled) {
            this.isEnabled = Objects.requireNonNull(isEnabled);
            return this;
        }
        public GetMysqlBackupDbSystemSnapshotBackupPolicyPitrPolicy build() {
            final var o = new GetMysqlBackupDbSystemSnapshotBackupPolicyPitrPolicy();
            o.isEnabled = isEnabled;
            return o;
        }
    }
}