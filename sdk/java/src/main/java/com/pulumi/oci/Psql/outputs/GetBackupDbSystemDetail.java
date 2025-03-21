// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Psql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetBackupDbSystemDetail {
    /**
     * @return OCID of the configuration that was applied on the source dbSystem at the time when backup was taken.
     * 
     */
    private String configId;
    /**
     * @return The major and minor versions of the database system software.
     * 
     */
    private String dbVersion;
    /**
     * @return Type of the database system.
     * 
     */
    private String systemType;

    private GetBackupDbSystemDetail() {}
    /**
     * @return OCID of the configuration that was applied on the source dbSystem at the time when backup was taken.
     * 
     */
    public String configId() {
        return this.configId;
    }
    /**
     * @return The major and minor versions of the database system software.
     * 
     */
    public String dbVersion() {
        return this.dbVersion;
    }
    /**
     * @return Type of the database system.
     * 
     */
    public String systemType() {
        return this.systemType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetBackupDbSystemDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String configId;
        private String dbVersion;
        private String systemType;
        public Builder() {}
        public Builder(GetBackupDbSystemDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.configId = defaults.configId;
    	      this.dbVersion = defaults.dbVersion;
    	      this.systemType = defaults.systemType;
        }

        @CustomType.Setter
        public Builder configId(String configId) {
            if (configId == null) {
              throw new MissingRequiredPropertyException("GetBackupDbSystemDetail", "configId");
            }
            this.configId = configId;
            return this;
        }
        @CustomType.Setter
        public Builder dbVersion(String dbVersion) {
            if (dbVersion == null) {
              throw new MissingRequiredPropertyException("GetBackupDbSystemDetail", "dbVersion");
            }
            this.dbVersion = dbVersion;
            return this;
        }
        @CustomType.Setter
        public Builder systemType(String systemType) {
            if (systemType == null) {
              throw new MissingRequiredPropertyException("GetBackupDbSystemDetail", "systemType");
            }
            this.systemType = systemType;
            return this;
        }
        public GetBackupDbSystemDetail build() {
            final var _resultValue = new GetBackupDbSystemDetail();
            _resultValue.configId = configId;
            _resultValue.dbVersion = dbVersion;
            _resultValue.systemType = systemType;
            return _resultValue;
        }
    }
}
