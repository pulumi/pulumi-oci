// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AutonomousContainerDatabaseDataguard {
    /**
     * @return The lag time between updates to the primary Autonomous Container Database and application of the redo data on the standby Autonomous Container Database, as computed by the reporting database. Example: `9 seconds`
     * 
     */
    private @Nullable String applyLag;
    /**
     * @return The rate at which redo logs are synchronized between the associated Autonomous Container Databases. Example: `180 Mb per second`
     * 
     */
    private @Nullable String applyRate;
    /**
     * @return Automatically selected by backend when observer is enabled.
     * 
     */
    private @Nullable String automaticFailoverTarget;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Container Database that has a relationship with the peer Autonomous Container Database. Used only by Autonomous Database on Dedicated Exadata Infrastructure.
     * 
     */
    private @Nullable String autonomousContainerDatabaseId;
    /**
     * @return The domain of the Autonomous Container Database
     * 
     */
    private @Nullable String availabilityDomain;
    /**
     * @return (Updatable) The lag time for my preference based on data loss tolerance in seconds.
     * 
     */
    private @Nullable Integer fastStartFailOverLagLimitInSeconds;
    /**
     * @return Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association. Input DataType: boolean. Example : is_automatic_failover_enabled = true.
     * 
     */
    private @Nullable Boolean isAutomaticFailoverEnabled;
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    private @Nullable String lifecycleDetails;
    /**
     * @return (Updatable) The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     * 
     */
    private @Nullable String protectionMode;
    /**
     * @return Automatically selected by backend based on the protection mode.
     * 
     */
    private @Nullable String redoTransportMode;
    /**
     * @return The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
     * 
     */
    private @Nullable String role;
    /**
     * @return The current state of the Autonomous Container Database.
     * 
     */
    private @Nullable String state;
    /**
     * @return The date and time the Autonomous Container Database was created.
     * 
     */
    private @Nullable String timeCreated;
    /**
     * @return Timestamp when the lags were last calculated for a standby.
     * 
     */
    private @Nullable String timeLagRefreshedOn;
    /**
     * @return The date and time when the last role change action happened.
     * 
     */
    private @Nullable String timeLastRoleChanged;
    /**
     * @return The date and time of the last update to the apply lag, apply rate, and transport lag values.
     * 
     */
    private @Nullable String timeLastSynced;
    /**
     * @return The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database. Example: `7 seconds`
     * 
     */
    private @Nullable String transportLag;

    private AutonomousContainerDatabaseDataguard() {}
    /**
     * @return The lag time between updates to the primary Autonomous Container Database and application of the redo data on the standby Autonomous Container Database, as computed by the reporting database. Example: `9 seconds`
     * 
     */
    public Optional<String> applyLag() {
        return Optional.ofNullable(this.applyLag);
    }
    /**
     * @return The rate at which redo logs are synchronized between the associated Autonomous Container Databases. Example: `180 Mb per second`
     * 
     */
    public Optional<String> applyRate() {
        return Optional.ofNullable(this.applyRate);
    }
    /**
     * @return Automatically selected by backend when observer is enabled.
     * 
     */
    public Optional<String> automaticFailoverTarget() {
        return Optional.ofNullable(this.automaticFailoverTarget);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Container Database that has a relationship with the peer Autonomous Container Database. Used only by Autonomous Database on Dedicated Exadata Infrastructure.
     * 
     */
    public Optional<String> autonomousContainerDatabaseId() {
        return Optional.ofNullable(this.autonomousContainerDatabaseId);
    }
    /**
     * @return The domain of the Autonomous Container Database
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }
    /**
     * @return (Updatable) The lag time for my preference based on data loss tolerance in seconds.
     * 
     */
    public Optional<Integer> fastStartFailOverLagLimitInSeconds() {
        return Optional.ofNullable(this.fastStartFailOverLagLimitInSeconds);
    }
    /**
     * @return Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association. Input DataType: boolean. Example : is_automatic_failover_enabled = true.
     * 
     */
    public Optional<Boolean> isAutomaticFailoverEnabled() {
        return Optional.ofNullable(this.isAutomaticFailoverEnabled);
    }
    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public Optional<String> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }
    /**
     * @return (Updatable) The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     * 
     */
    public Optional<String> protectionMode() {
        return Optional.ofNullable(this.protectionMode);
    }
    /**
     * @return Automatically selected by backend based on the protection mode.
     * 
     */
    public Optional<String> redoTransportMode() {
        return Optional.ofNullable(this.redoTransportMode);
    }
    /**
     * @return The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
     * 
     */
    public Optional<String> role() {
        return Optional.ofNullable(this.role);
    }
    /**
     * @return The current state of the Autonomous Container Database.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The date and time the Autonomous Container Database was created.
     * 
     */
    public Optional<String> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }
    /**
     * @return Timestamp when the lags were last calculated for a standby.
     * 
     */
    public Optional<String> timeLagRefreshedOn() {
        return Optional.ofNullable(this.timeLagRefreshedOn);
    }
    /**
     * @return The date and time when the last role change action happened.
     * 
     */
    public Optional<String> timeLastRoleChanged() {
        return Optional.ofNullable(this.timeLastRoleChanged);
    }
    /**
     * @return The date and time of the last update to the apply lag, apply rate, and transport lag values.
     * 
     */
    public Optional<String> timeLastSynced() {
        return Optional.ofNullable(this.timeLastSynced);
    }
    /**
     * @return The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database. Example: `7 seconds`
     * 
     */
    public Optional<String> transportLag() {
        return Optional.ofNullable(this.transportLag);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AutonomousContainerDatabaseDataguard defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String applyLag;
        private @Nullable String applyRate;
        private @Nullable String automaticFailoverTarget;
        private @Nullable String autonomousContainerDatabaseId;
        private @Nullable String availabilityDomain;
        private @Nullable Integer fastStartFailOverLagLimitInSeconds;
        private @Nullable Boolean isAutomaticFailoverEnabled;
        private @Nullable String lifecycleDetails;
        private @Nullable String protectionMode;
        private @Nullable String redoTransportMode;
        private @Nullable String role;
        private @Nullable String state;
        private @Nullable String timeCreated;
        private @Nullable String timeLagRefreshedOn;
        private @Nullable String timeLastRoleChanged;
        private @Nullable String timeLastSynced;
        private @Nullable String transportLag;
        public Builder() {}
        public Builder(AutonomousContainerDatabaseDataguard defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applyLag = defaults.applyLag;
    	      this.applyRate = defaults.applyRate;
    	      this.automaticFailoverTarget = defaults.automaticFailoverTarget;
    	      this.autonomousContainerDatabaseId = defaults.autonomousContainerDatabaseId;
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.fastStartFailOverLagLimitInSeconds = defaults.fastStartFailOverLagLimitInSeconds;
    	      this.isAutomaticFailoverEnabled = defaults.isAutomaticFailoverEnabled;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.protectionMode = defaults.protectionMode;
    	      this.redoTransportMode = defaults.redoTransportMode;
    	      this.role = defaults.role;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeLagRefreshedOn = defaults.timeLagRefreshedOn;
    	      this.timeLastRoleChanged = defaults.timeLastRoleChanged;
    	      this.timeLastSynced = defaults.timeLastSynced;
    	      this.transportLag = defaults.transportLag;
        }

        @CustomType.Setter
        public Builder applyLag(@Nullable String applyLag) {

            this.applyLag = applyLag;
            return this;
        }
        @CustomType.Setter
        public Builder applyRate(@Nullable String applyRate) {

            this.applyRate = applyRate;
            return this;
        }
        @CustomType.Setter
        public Builder automaticFailoverTarget(@Nullable String automaticFailoverTarget) {

            this.automaticFailoverTarget = automaticFailoverTarget;
            return this;
        }
        @CustomType.Setter
        public Builder autonomousContainerDatabaseId(@Nullable String autonomousContainerDatabaseId) {

            this.autonomousContainerDatabaseId = autonomousContainerDatabaseId;
            return this;
        }
        @CustomType.Setter
        public Builder availabilityDomain(@Nullable String availabilityDomain) {

            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder fastStartFailOverLagLimitInSeconds(@Nullable Integer fastStartFailOverLagLimitInSeconds) {

            this.fastStartFailOverLagLimitInSeconds = fastStartFailOverLagLimitInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder isAutomaticFailoverEnabled(@Nullable Boolean isAutomaticFailoverEnabled) {

            this.isAutomaticFailoverEnabled = isAutomaticFailoverEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(@Nullable String lifecycleDetails) {

            this.lifecycleDetails = lifecycleDetails;
            return this;
        }
        @CustomType.Setter
        public Builder protectionMode(@Nullable String protectionMode) {

            this.protectionMode = protectionMode;
            return this;
        }
        @CustomType.Setter
        public Builder redoTransportMode(@Nullable String redoTransportMode) {

            this.redoTransportMode = redoTransportMode;
            return this;
        }
        @CustomType.Setter
        public Builder role(@Nullable String role) {

            this.role = role;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(@Nullable String timeCreated) {

            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeLagRefreshedOn(@Nullable String timeLagRefreshedOn) {

            this.timeLagRefreshedOn = timeLagRefreshedOn;
            return this;
        }
        @CustomType.Setter
        public Builder timeLastRoleChanged(@Nullable String timeLastRoleChanged) {

            this.timeLastRoleChanged = timeLastRoleChanged;
            return this;
        }
        @CustomType.Setter
        public Builder timeLastSynced(@Nullable String timeLastSynced) {

            this.timeLastSynced = timeLastSynced;
            return this;
        }
        @CustomType.Setter
        public Builder transportLag(@Nullable String transportLag) {

            this.transportLag = transportLag;
            return this;
        }
        public AutonomousContainerDatabaseDataguard build() {
            final var _resultValue = new AutonomousContainerDatabaseDataguard();
            _resultValue.applyLag = applyLag;
            _resultValue.applyRate = applyRate;
            _resultValue.automaticFailoverTarget = automaticFailoverTarget;
            _resultValue.autonomousContainerDatabaseId = autonomousContainerDatabaseId;
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.fastStartFailOverLagLimitInSeconds = fastStartFailOverLagLimitInSeconds;
            _resultValue.isAutomaticFailoverEnabled = isAutomaticFailoverEnabled;
            _resultValue.lifecycleDetails = lifecycleDetails;
            _resultValue.protectionMode = protectionMode;
            _resultValue.redoTransportMode = redoTransportMode;
            _resultValue.role = role;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeLagRefreshedOn = timeLagRefreshedOn;
            _resultValue.timeLastRoleChanged = timeLastRoleChanged;
            _resultValue.timeLastSynced = timeLastSynced;
            _resultValue.transportLag = transportLag;
            return _resultValue;
        }
    }
}
