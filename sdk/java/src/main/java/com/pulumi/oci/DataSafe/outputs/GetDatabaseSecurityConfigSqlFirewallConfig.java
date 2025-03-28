// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDatabaseSecurityConfigSqlFirewallConfig {
    /**
     * @return Specifies whether the firewall should include or exclude the database internal job activities.
     * 
     */
    private String excludeJob;
    /**
     * @return Specifies if the firewall is enabled or disabled on the target database.
     * 
     */
    private String status;
    /**
     * @return The most recent time when the firewall status is updated, in the format defined by RFC3339.
     * 
     */
    private String timeStatusUpdated;
    /**
     * @return Specifies whether Data Safe should automatically purge the violation logs  from the database after collecting the violation logs and persisting on Data Safe.
     * 
     */
    private String violationLogAutoPurge;

    private GetDatabaseSecurityConfigSqlFirewallConfig() {}
    /**
     * @return Specifies whether the firewall should include or exclude the database internal job activities.
     * 
     */
    public String excludeJob() {
        return this.excludeJob;
    }
    /**
     * @return Specifies if the firewall is enabled or disabled on the target database.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return The most recent time when the firewall status is updated, in the format defined by RFC3339.
     * 
     */
    public String timeStatusUpdated() {
        return this.timeStatusUpdated;
    }
    /**
     * @return Specifies whether Data Safe should automatically purge the violation logs  from the database after collecting the violation logs and persisting on Data Safe.
     * 
     */
    public String violationLogAutoPurge() {
        return this.violationLogAutoPurge;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseSecurityConfigSqlFirewallConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String excludeJob;
        private String status;
        private String timeStatusUpdated;
        private String violationLogAutoPurge;
        public Builder() {}
        public Builder(GetDatabaseSecurityConfigSqlFirewallConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.excludeJob = defaults.excludeJob;
    	      this.status = defaults.status;
    	      this.timeStatusUpdated = defaults.timeStatusUpdated;
    	      this.violationLogAutoPurge = defaults.violationLogAutoPurge;
        }

        @CustomType.Setter
        public Builder excludeJob(String excludeJob) {
            if (excludeJob == null) {
              throw new MissingRequiredPropertyException("GetDatabaseSecurityConfigSqlFirewallConfig", "excludeJob");
            }
            this.excludeJob = excludeJob;
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetDatabaseSecurityConfigSqlFirewallConfig", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder timeStatusUpdated(String timeStatusUpdated) {
            if (timeStatusUpdated == null) {
              throw new MissingRequiredPropertyException("GetDatabaseSecurityConfigSqlFirewallConfig", "timeStatusUpdated");
            }
            this.timeStatusUpdated = timeStatusUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder violationLogAutoPurge(String violationLogAutoPurge) {
            if (violationLogAutoPurge == null) {
              throw new MissingRequiredPropertyException("GetDatabaseSecurityConfigSqlFirewallConfig", "violationLogAutoPurge");
            }
            this.violationLogAutoPurge = violationLogAutoPurge;
            return this;
        }
        public GetDatabaseSecurityConfigSqlFirewallConfig build() {
            final var _resultValue = new GetDatabaseSecurityConfigSqlFirewallConfig();
            _resultValue.excludeJob = excludeJob;
            _resultValue.status = status;
            _resultValue.timeStatusUpdated = timeStatusUpdated;
            _resultValue.violationLogAutoPurge = violationLogAutoPurge;
            return _resultValue;
        }
    }
}
