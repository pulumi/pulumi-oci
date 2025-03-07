// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAutonomousContainerDatabasesAutonomousContainerDatabaseRecoveryApplianceDetail {
    /**
     * @return The storage size of the backup destination allocated for an Autonomous Container Database to store backups on the recovery appliance, in GBs, rounded to the nearest integer.
     * 
     */
    private Integer allocatedStorageSizeInGbs;
    /**
     * @return Number of days between the current and earliest point of recoverability covered by automatic backups.
     * 
     */
    private Integer recoveryWindowInDays;
    /**
     * @return The time when the recovery appliance details are updated.
     * 
     */
    private String timeRecoveryApplianceDetailsUpdated;

    private GetAutonomousContainerDatabasesAutonomousContainerDatabaseRecoveryApplianceDetail() {}
    /**
     * @return The storage size of the backup destination allocated for an Autonomous Container Database to store backups on the recovery appliance, in GBs, rounded to the nearest integer.
     * 
     */
    public Integer allocatedStorageSizeInGbs() {
        return this.allocatedStorageSizeInGbs;
    }
    /**
     * @return Number of days between the current and earliest point of recoverability covered by automatic backups.
     * 
     */
    public Integer recoveryWindowInDays() {
        return this.recoveryWindowInDays;
    }
    /**
     * @return The time when the recovery appliance details are updated.
     * 
     */
    public String timeRecoveryApplianceDetailsUpdated() {
        return this.timeRecoveryApplianceDetailsUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousContainerDatabasesAutonomousContainerDatabaseRecoveryApplianceDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer allocatedStorageSizeInGbs;
        private Integer recoveryWindowInDays;
        private String timeRecoveryApplianceDetailsUpdated;
        public Builder() {}
        public Builder(GetAutonomousContainerDatabasesAutonomousContainerDatabaseRecoveryApplianceDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allocatedStorageSizeInGbs = defaults.allocatedStorageSizeInGbs;
    	      this.recoveryWindowInDays = defaults.recoveryWindowInDays;
    	      this.timeRecoveryApplianceDetailsUpdated = defaults.timeRecoveryApplianceDetailsUpdated;
        }

        @CustomType.Setter
        public Builder allocatedStorageSizeInGbs(Integer allocatedStorageSizeInGbs) {
            if (allocatedStorageSizeInGbs == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabasesAutonomousContainerDatabaseRecoveryApplianceDetail", "allocatedStorageSizeInGbs");
            }
            this.allocatedStorageSizeInGbs = allocatedStorageSizeInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder recoveryWindowInDays(Integer recoveryWindowInDays) {
            if (recoveryWindowInDays == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabasesAutonomousContainerDatabaseRecoveryApplianceDetail", "recoveryWindowInDays");
            }
            this.recoveryWindowInDays = recoveryWindowInDays;
            return this;
        }
        @CustomType.Setter
        public Builder timeRecoveryApplianceDetailsUpdated(String timeRecoveryApplianceDetailsUpdated) {
            if (timeRecoveryApplianceDetailsUpdated == null) {
              throw new MissingRequiredPropertyException("GetAutonomousContainerDatabasesAutonomousContainerDatabaseRecoveryApplianceDetail", "timeRecoveryApplianceDetailsUpdated");
            }
            this.timeRecoveryApplianceDetailsUpdated = timeRecoveryApplianceDetailsUpdated;
            return this;
        }
        public GetAutonomousContainerDatabasesAutonomousContainerDatabaseRecoveryApplianceDetail build() {
            final var _resultValue = new GetAutonomousContainerDatabasesAutonomousContainerDatabaseRecoveryApplianceDetail();
            _resultValue.allocatedStorageSizeInGbs = allocatedStorageSizeInGbs;
            _resultValue.recoveryWindowInDays = recoveryWindowInDays;
            _resultValue.timeRecoveryApplianceDetailsUpdated = timeRecoveryApplianceDetailsUpdated;
            return _resultValue;
        }
    }
}
