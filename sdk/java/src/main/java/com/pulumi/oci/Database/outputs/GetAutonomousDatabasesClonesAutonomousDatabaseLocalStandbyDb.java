// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetAutonomousDatabasesClonesAutonomousDatabaseLocalStandbyDb {
    private String availabilityDomain;
    /**
     * @return The amount of time, in seconds, that the data of the standby database lags the data of the primary database. Can be used to determine the potential data loss in the event of a failover.
     * 
     */
    private Integer lagTimeInSeconds;
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The component chosen for maintenance.
     * 
     */
    private String maintenanceTargetComponent;
    /**
     * @return A filter to return only resources that match the given lifecycle state exactly.
     * 
     */
    private String state;
    /**
     * @return The date and time the Autonomous Data Guard role was switched for the Autonomous Database. For databases that have standbys in both the primary Data Guard region and a remote Data Guard standby region, this is the latest timestamp of either the database using the &#34;primary&#34; role in the primary Data Guard region, or database located in the remote Data Guard standby region.
     * 
     */
    private String timeDataGuardRoleChanged;
    /**
     * @return The date and time the Disaster Recovery role was switched for the standby Autonomous Database.
     * 
     */
    private String timeDisasterRecoveryRoleChanged;
    /**
     * @return The date and time when maintenance will begin.
     * 
     */
    private String timeMaintenanceBegin;
    /**
     * @return The date and time when maintenance will end.
     * 
     */
    private String timeMaintenanceEnd;

    private GetAutonomousDatabasesClonesAutonomousDatabaseLocalStandbyDb() {}
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The amount of time, in seconds, that the data of the standby database lags the data of the primary database. Can be used to determine the potential data loss in the event of a failover.
     * 
     */
    public Integer lagTimeInSeconds() {
        return this.lagTimeInSeconds;
    }
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The component chosen for maintenance.
     * 
     */
    public String maintenanceTargetComponent() {
        return this.maintenanceTargetComponent;
    }
    /**
     * @return A filter to return only resources that match the given lifecycle state exactly.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The date and time the Autonomous Data Guard role was switched for the Autonomous Database. For databases that have standbys in both the primary Data Guard region and a remote Data Guard standby region, this is the latest timestamp of either the database using the &#34;primary&#34; role in the primary Data Guard region, or database located in the remote Data Guard standby region.
     * 
     */
    public String timeDataGuardRoleChanged() {
        return this.timeDataGuardRoleChanged;
    }
    /**
     * @return The date and time the Disaster Recovery role was switched for the standby Autonomous Database.
     * 
     */
    public String timeDisasterRecoveryRoleChanged() {
        return this.timeDisasterRecoveryRoleChanged;
    }
    /**
     * @return The date and time when maintenance will begin.
     * 
     */
    public String timeMaintenanceBegin() {
        return this.timeMaintenanceBegin;
    }
    /**
     * @return The date and time when maintenance will end.
     * 
     */
    public String timeMaintenanceEnd() {
        return this.timeMaintenanceEnd;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousDatabasesClonesAutonomousDatabaseLocalStandbyDb defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private Integer lagTimeInSeconds;
        private String lifecycleDetails;
        private String maintenanceTargetComponent;
        private String state;
        private String timeDataGuardRoleChanged;
        private String timeDisasterRecoveryRoleChanged;
        private String timeMaintenanceBegin;
        private String timeMaintenanceEnd;
        public Builder() {}
        public Builder(GetAutonomousDatabasesClonesAutonomousDatabaseLocalStandbyDb defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.lagTimeInSeconds = defaults.lagTimeInSeconds;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.maintenanceTargetComponent = defaults.maintenanceTargetComponent;
    	      this.state = defaults.state;
    	      this.timeDataGuardRoleChanged = defaults.timeDataGuardRoleChanged;
    	      this.timeDisasterRecoveryRoleChanged = defaults.timeDisasterRecoveryRoleChanged;
    	      this.timeMaintenanceBegin = defaults.timeMaintenanceBegin;
    	      this.timeMaintenanceEnd = defaults.timeMaintenanceEnd;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            if (availabilityDomain == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseLocalStandbyDb", "availabilityDomain");
            }
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder lagTimeInSeconds(Integer lagTimeInSeconds) {
            if (lagTimeInSeconds == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseLocalStandbyDb", "lagTimeInSeconds");
            }
            this.lagTimeInSeconds = lagTimeInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            if (lifecycleDetails == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseLocalStandbyDb", "lifecycleDetails");
            }
            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder maintenanceTargetComponent(String maintenanceTargetComponent) {
            if (maintenanceTargetComponent == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseLocalStandbyDb", "maintenanceTargetComponent");
            }
            this.maintenanceTargetComponent = maintenanceTargetComponent;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseLocalStandbyDb", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeDataGuardRoleChanged(String timeDataGuardRoleChanged) {
            if (timeDataGuardRoleChanged == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseLocalStandbyDb", "timeDataGuardRoleChanged");
            }
            this.timeDataGuardRoleChanged = timeDataGuardRoleChanged;
            return this;
        }
        @CustomType.Setter
        public Builder timeDisasterRecoveryRoleChanged(String timeDisasterRecoveryRoleChanged) {
            if (timeDisasterRecoveryRoleChanged == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseLocalStandbyDb", "timeDisasterRecoveryRoleChanged");
            }
            this.timeDisasterRecoveryRoleChanged = timeDisasterRecoveryRoleChanged;
            return this;
        }
        @CustomType.Setter
        public Builder timeMaintenanceBegin(String timeMaintenanceBegin) {
            if (timeMaintenanceBegin == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseLocalStandbyDb", "timeMaintenanceBegin");
            }
            this.timeMaintenanceBegin = timeMaintenanceBegin;
            return this;
        }
        @CustomType.Setter
        public Builder timeMaintenanceEnd(String timeMaintenanceEnd) {
            if (timeMaintenanceEnd == null) {
              throw new MissingRequiredPropertyException("GetAutonomousDatabasesClonesAutonomousDatabaseLocalStandbyDb", "timeMaintenanceEnd");
            }
            this.timeMaintenanceEnd = timeMaintenanceEnd;
            return this;
        }
        public GetAutonomousDatabasesClonesAutonomousDatabaseLocalStandbyDb build() {
            final var _resultValue = new GetAutonomousDatabasesClonesAutonomousDatabaseLocalStandbyDb();
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.lagTimeInSeconds = lagTimeInSeconds;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.maintenanceTargetComponent = maintenanceTargetComponent;
            _resultValue.state = state;
            _resultValue.timeDataGuardRoleChanged = timeDataGuardRoleChanged;
            _resultValue.timeDisasterRecoveryRoleChanged = timeDisasterRecoveryRoleChanged;
            _resultValue.timeMaintenanceBegin = timeMaintenanceBegin;
            _resultValue.timeMaintenanceEnd = timeMaintenanceEnd;
            return _resultValue;
        }
    }
}
