// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Psql.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class BackupDbSystemDetail {
    /**
     * @return OCID of the configuration that was applied on the source dbSystem at the time when backup was taken.
     * 
     */
    private @Nullable String configId;
    /**
     * @return The major and minor versions of the database system software.
     * 
     */
    private @Nullable String dbVersion;
    /**
     * @return Type of the database system.
     * 
     */
    private @Nullable String systemType;

    private BackupDbSystemDetail() {}
    /**
     * @return OCID of the configuration that was applied on the source dbSystem at the time when backup was taken.
     * 
     */
    public Optional<String> configId() {
        return Optional.ofNullable(this.configId);
    }
    /**
     * @return The major and minor versions of the database system software.
     * 
     */
    public Optional<String> dbVersion() {
        return Optional.ofNullable(this.dbVersion);
    }
    /**
     * @return Type of the database system.
     * 
     */
    public Optional<String> systemType() {
        return Optional.ofNullable(this.systemType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(BackupDbSystemDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String configId;
        private @Nullable String dbVersion;
        private @Nullable String systemType;
        public Builder() {}
        public Builder(BackupDbSystemDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.configId = defaults.configId;
    	      this.dbVersion = defaults.dbVersion;
    	      this.systemType = defaults.systemType;
        }

        @CustomType.Setter
        public Builder configId(@Nullable String configId) {

            this.configId = configId;
            return this;
        }
        @CustomType.Setter
        public Builder dbVersion(@Nullable String dbVersion) {

            this.dbVersion = dbVersion;
            return this;
        }
        @CustomType.Setter
        public Builder systemType(@Nullable String systemType) {

            this.systemType = systemType;
            return this;
        }
        public BackupDbSystemDetail build() {
            final var _resultValue = new BackupDbSystemDetail();
            _resultValue.configId = configId;
            _resultValue.dbVersion = dbVersion;
            _resultValue.systemType = systemType;
            return _resultValue;
        }
    }
}
