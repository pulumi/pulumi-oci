// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAutonomousDbVersionsAutonomousDbVersion {
    /**
     * @return A filter to return only autonomous database resources that match the specified workload type.
     * 
     */
    private String dbWorkload;
    /**
     * @return A URL that points to a detailed description of the Autonomous Database version.
     * 
     */
    private String details;
    /**
     * @return True if the database uses [dedicated Exadata infrastructure](https://docs.oracle.com/en/cloud/paas/autonomous-database/index.html).
     * 
     */
    private Boolean isDedicated;
    /**
     * @return True if this version of the Oracle Database software&#39;s default is free.
     * 
     */
    private Boolean isDefaultForFree;
    /**
     * @return True if this version of the Oracle Database software&#39;s default is paid.
     * 
     */
    private Boolean isDefaultForPaid;
    /**
     * @return True if this version of the Oracle Database software can be used for Always-Free Autonomous Databases.
     * 
     */
    private Boolean isFreeTierEnabled;
    /**
     * @return True if this version of the Oracle Database software has payments enabled.
     * 
     */
    private Boolean isPaidEnabled;
    /**
     * @return A valid Oracle Database version for Autonomous Database.
     * 
     */
    private String version;

    private GetAutonomousDbVersionsAutonomousDbVersion() {}
    /**
     * @return A filter to return only autonomous database resources that match the specified workload type.
     * 
     */
    public String dbWorkload() {
        return this.dbWorkload;
    }
    /**
     * @return A URL that points to a detailed description of the Autonomous Database version.
     * 
     */
    public String details() {
        return this.details;
    }
    /**
     * @return True if the database uses [dedicated Exadata infrastructure](https://docs.oracle.com/en/cloud/paas/autonomous-database/index.html).
     * 
     */
    public Boolean isDedicated() {
        return this.isDedicated;
    }
    /**
     * @return True if this version of the Oracle Database software&#39;s default is free.
     * 
     */
    public Boolean isDefaultForFree() {
        return this.isDefaultForFree;
    }
    /**
     * @return True if this version of the Oracle Database software&#39;s default is paid.
     * 
     */
    public Boolean isDefaultForPaid() {
        return this.isDefaultForPaid;
    }
    /**
     * @return True if this version of the Oracle Database software can be used for Always-Free Autonomous Databases.
     * 
     */
    public Boolean isFreeTierEnabled() {
        return this.isFreeTierEnabled;
    }
    /**
     * @return True if this version of the Oracle Database software has payments enabled.
     * 
     */
    public Boolean isPaidEnabled() {
        return this.isPaidEnabled;
    }
    /**
     * @return A valid Oracle Database version for Autonomous Database.
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousDbVersionsAutonomousDbVersion defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String dbWorkload;
        private String details;
        private Boolean isDedicated;
        private Boolean isDefaultForFree;
        private Boolean isDefaultForPaid;
        private Boolean isFreeTierEnabled;
        private Boolean isPaidEnabled;
        private String version;
        public Builder() {}
        public Builder(GetAutonomousDbVersionsAutonomousDbVersion defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dbWorkload = defaults.dbWorkload;
    	      this.details = defaults.details;
    	      this.isDedicated = defaults.isDedicated;
    	      this.isDefaultForFree = defaults.isDefaultForFree;
    	      this.isDefaultForPaid = defaults.isDefaultForPaid;
    	      this.isFreeTierEnabled = defaults.isFreeTierEnabled;
    	      this.isPaidEnabled = defaults.isPaidEnabled;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder dbWorkload(String dbWorkload) {
            if (dbWorkload == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDbVersionsAutonomousDbVersion", "dbWorkload");
            }
            this.dbWorkload = dbWorkload;
            return this;
        }
        @CustomType.Setter
        public Builder details(String details) {
            if (details == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDbVersionsAutonomousDbVersion", "details");
            }
            this.details = details;
            return this;
        }
        @CustomType.Setter
        public Builder isDedicated(Boolean isDedicated) {
            if (isDedicated == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDbVersionsAutonomousDbVersion", "isDedicated");
            }
            this.isDedicated = isDedicated;
            return this;
        }
        @CustomType.Setter
        public Builder isDefaultForFree(Boolean isDefaultForFree) {
            if (isDefaultForFree == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDbVersionsAutonomousDbVersion", "isDefaultForFree");
            }
            this.isDefaultForFree = isDefaultForFree;
            return this;
        }
        @CustomType.Setter
        public Builder isDefaultForPaid(Boolean isDefaultForPaid) {
            if (isDefaultForPaid == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDbVersionsAutonomousDbVersion", "isDefaultForPaid");
            }
            this.isDefaultForPaid = isDefaultForPaid;
            return this;
        }
        @CustomType.Setter
        public Builder isFreeTierEnabled(Boolean isFreeTierEnabled) {
            if (isFreeTierEnabled == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDbVersionsAutonomousDbVersion", "isFreeTierEnabled");
            }
            this.isFreeTierEnabled = isFreeTierEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder isPaidEnabled(Boolean isPaidEnabled) {
            if (isPaidEnabled == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDbVersionsAutonomousDbVersion", "isPaidEnabled");
            }
            this.isPaidEnabled = isPaidEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDbVersionsAutonomousDbVersion", "version");
            }
            this.version = version;
            return this;
        }
        public GetAutonomousDbVersionsAutonomousDbVersion build() {
            final var _resultValue = new GetAutonomousDbVersionsAutonomousDbVersion();
            _resultValue.dbWorkload = dbWorkload;
            _resultValue.details = details;
            _resultValue.isDedicated = isDedicated;
            _resultValue.isDefaultForFree = isDefaultForFree;
            _resultValue.isDefaultForPaid = isDefaultForPaid;
            _resultValue.isFreeTierEnabled = isFreeTierEnabled;
            _resultValue.isPaidEnabled = isPaidEnabled;
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
