// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MysqlDbSystemBackupPolicyPitrPolicy {
    /**
     * @return (Updatable) Specifies if PITR is enabled or disabled.
     * 
     */
    private @Nullable Boolean isEnabled;

    private MysqlDbSystemBackupPolicyPitrPolicy() {}
    /**
     * @return (Updatable) Specifies if PITR is enabled or disabled.
     * 
     */
    public Optional<Boolean> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MysqlDbSystemBackupPolicyPitrPolicy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean isEnabled;
        public Builder() {}
        public Builder(MysqlDbSystemBackupPolicyPitrPolicy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isEnabled = defaults.isEnabled;
        }

        @CustomType.Setter
        public Builder isEnabled(@Nullable Boolean isEnabled) {

            this.isEnabled = isEnabled;
            return this;
        }
        public MysqlDbSystemBackupPolicyPitrPolicy build() {
            final var _resultValue = new MysqlDbSystemBackupPolicyPitrPolicy();
            _resultValue.isEnabled = isEnabled;
            return _resultValue;
        }
    }
}
