// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AutonomousContainerDatabaseAddStandbyDataguardArgs extends com.pulumi.resources.ResourceArgs {

    public static final AutonomousContainerDatabaseAddStandbyDataguardArgs Empty = new AutonomousContainerDatabaseAddStandbyDataguardArgs();

    /**
     * The lag time between updates to the primary Autonomous Container Database and application of the redo data on the standby Autonomous Container Database, as computed by the reporting database. Example: `9 seconds`
     * 
     */
    @Import(name="applyLag")
    private @Nullable Output<String> applyLag;

    /**
     * @return The lag time between updates to the primary Autonomous Container Database and application of the redo data on the standby Autonomous Container Database, as computed by the reporting database. Example: `9 seconds`
     * 
     */
    public Optional<Output<String>> applyLag() {
        return Optional.ofNullable(this.applyLag);
    }

    /**
     * The rate at which redo logs are synchronized between the associated Autonomous Container Databases. Example: `180 Mb per second`
     * 
     */
    @Import(name="applyRate")
    private @Nullable Output<String> applyRate;

    /**
     * @return The rate at which redo logs are synchronized between the associated Autonomous Container Databases. Example: `180 Mb per second`
     * 
     */
    public Optional<Output<String>> applyRate() {
        return Optional.ofNullable(this.applyRate);
    }

    /**
     * Automatically selected by backend when observer is enabled.
     * 
     */
    @Import(name="automaticFailoverTarget")
    private @Nullable Output<String> automaticFailoverTarget;

    /**
     * @return Automatically selected by backend when observer is enabled.
     * 
     */
    public Optional<Output<String>> automaticFailoverTarget() {
        return Optional.ofNullable(this.automaticFailoverTarget);
    }

    /**
     * The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="autonomousContainerDatabaseId")
    private @Nullable Output<String> autonomousContainerDatabaseId;

    /**
     * @return The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Optional<Output<String>> autonomousContainerDatabaseId() {
        return Optional.ofNullable(this.autonomousContainerDatabaseId);
    }

    /**
     * The domain of the Autonomous Container Database
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable Output<String> availabilityDomain;

    /**
     * @return The domain of the Autonomous Container Database
     * 
     */
    public Optional<Output<String>> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * The lag time for my preference based on data loss tolerance in seconds.
     * 
     */
    @Import(name="fastStartFailOverLagLimitInSeconds")
    private @Nullable Output<Integer> fastStartFailOverLagLimitInSeconds;

    /**
     * @return The lag time for my preference based on data loss tolerance in seconds.
     * 
     */
    public Optional<Output<Integer>> fastStartFailOverLagLimitInSeconds() {
        return Optional.ofNullable(this.fastStartFailOverLagLimitInSeconds);
    }

    /**
     * Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
     * 
     */
    @Import(name="isAutomaticFailoverEnabled")
    private @Nullable Output<Boolean> isAutomaticFailoverEnabled;

    /**
     * @return Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
     * 
     */
    public Optional<Output<Boolean>> isAutomaticFailoverEnabled() {
        return Optional.ofNullable(this.isAutomaticFailoverEnabled);
    }

    /**
     * Additional information about the current lifecycle state.
     * 
     */
    @Import(name="lifecycleDetails")
    private @Nullable Output<String> lifecycleDetails;

    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public Optional<Output<String>> lifecycleDetails() {
        return Optional.ofNullable(this.lifecycleDetails);
    }

    /**
     * The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     * 
     */
    @Import(name="protectionMode")
    private @Nullable Output<String> protectionMode;

    /**
     * @return The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
     * 
     */
    public Optional<Output<String>> protectionMode() {
        return Optional.ofNullable(this.protectionMode);
    }

    /**
     * Automatically selected by backend based on the protection mode.
     * 
     */
    @Import(name="redoTransportMode")
    private @Nullable Output<String> redoTransportMode;

    /**
     * @return Automatically selected by backend based on the protection mode.
     * 
     */
    public Optional<Output<String>> redoTransportMode() {
        return Optional.ofNullable(this.redoTransportMode);
    }

    /**
     * The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
     * 
     */
    @Import(name="role")
    private @Nullable Output<String> role;

    /**
     * @return The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
     * 
     */
    public Optional<Output<String>> role() {
        return Optional.ofNullable(this.role);
    }

    /**
     * The current state of the Autonomous Container Database.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the Autonomous Container Database.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time the Autonomous Container Database was created.
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the Autonomous Container Database was created.
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * Timestamp when the lags were last calculated for a standby.
     * 
     */
    @Import(name="timeLagRefreshedOn")
    private @Nullable Output<String> timeLagRefreshedOn;

    /**
     * @return Timestamp when the lags were last calculated for a standby.
     * 
     */
    public Optional<Output<String>> timeLagRefreshedOn() {
        return Optional.ofNullable(this.timeLagRefreshedOn);
    }

    /**
     * The date and time when the last role change action happened.
     * 
     */
    @Import(name="timeLastRoleChanged")
    private @Nullable Output<String> timeLastRoleChanged;

    /**
     * @return The date and time when the last role change action happened.
     * 
     */
    public Optional<Output<String>> timeLastRoleChanged() {
        return Optional.ofNullable(this.timeLastRoleChanged);
    }

    /**
     * The date and time of the last update to the apply lag, apply rate, and transport lag values.
     * 
     */
    @Import(name="timeLastSynced")
    private @Nullable Output<String> timeLastSynced;

    /**
     * @return The date and time of the last update to the apply lag, apply rate, and transport lag values.
     * 
     */
    public Optional<Output<String>> timeLastSynced() {
        return Optional.ofNullable(this.timeLastSynced);
    }

    /**
     * The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database. Example: `7 seconds`
     * 
     */
    @Import(name="transportLag")
    private @Nullable Output<String> transportLag;

    /**
     * @return The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database. Example: `7 seconds`
     * 
     */
    public Optional<Output<String>> transportLag() {
        return Optional.ofNullable(this.transportLag);
    }

    private AutonomousContainerDatabaseAddStandbyDataguardArgs() {}

    private AutonomousContainerDatabaseAddStandbyDataguardArgs(AutonomousContainerDatabaseAddStandbyDataguardArgs $) {
        this.applyLag = $.applyLag;
        this.applyRate = $.applyRate;
        this.automaticFailoverTarget = $.automaticFailoverTarget;
        this.autonomousContainerDatabaseId = $.autonomousContainerDatabaseId;
        this.availabilityDomain = $.availabilityDomain;
        this.fastStartFailOverLagLimitInSeconds = $.fastStartFailOverLagLimitInSeconds;
        this.isAutomaticFailoverEnabled = $.isAutomaticFailoverEnabled;
        this.lifecycleDetails = $.lifecycleDetails;
        this.protectionMode = $.protectionMode;
        this.redoTransportMode = $.redoTransportMode;
        this.role = $.role;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
        this.timeLagRefreshedOn = $.timeLagRefreshedOn;
        this.timeLastRoleChanged = $.timeLastRoleChanged;
        this.timeLastSynced = $.timeLastSynced;
        this.transportLag = $.transportLag;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AutonomousContainerDatabaseAddStandbyDataguardArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AutonomousContainerDatabaseAddStandbyDataguardArgs $;

        public Builder() {
            $ = new AutonomousContainerDatabaseAddStandbyDataguardArgs();
        }

        public Builder(AutonomousContainerDatabaseAddStandbyDataguardArgs defaults) {
            $ = new AutonomousContainerDatabaseAddStandbyDataguardArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param applyLag The lag time between updates to the primary Autonomous Container Database and application of the redo data on the standby Autonomous Container Database, as computed by the reporting database. Example: `9 seconds`
         * 
         * @return builder
         * 
         */
        public Builder applyLag(@Nullable Output<String> applyLag) {
            $.applyLag = applyLag;
            return this;
        }

        /**
         * @param applyLag The lag time between updates to the primary Autonomous Container Database and application of the redo data on the standby Autonomous Container Database, as computed by the reporting database. Example: `9 seconds`
         * 
         * @return builder
         * 
         */
        public Builder applyLag(String applyLag) {
            return applyLag(Output.of(applyLag));
        }

        /**
         * @param applyRate The rate at which redo logs are synchronized between the associated Autonomous Container Databases. Example: `180 Mb per second`
         * 
         * @return builder
         * 
         */
        public Builder applyRate(@Nullable Output<String> applyRate) {
            $.applyRate = applyRate;
            return this;
        }

        /**
         * @param applyRate The rate at which redo logs are synchronized between the associated Autonomous Container Databases. Example: `180 Mb per second`
         * 
         * @return builder
         * 
         */
        public Builder applyRate(String applyRate) {
            return applyRate(Output.of(applyRate));
        }

        /**
         * @param automaticFailoverTarget Automatically selected by backend when observer is enabled.
         * 
         * @return builder
         * 
         */
        public Builder automaticFailoverTarget(@Nullable Output<String> automaticFailoverTarget) {
            $.automaticFailoverTarget = automaticFailoverTarget;
            return this;
        }

        /**
         * @param automaticFailoverTarget Automatically selected by backend when observer is enabled.
         * 
         * @return builder
         * 
         */
        public Builder automaticFailoverTarget(String automaticFailoverTarget) {
            return automaticFailoverTarget(Output.of(automaticFailoverTarget));
        }

        /**
         * @param autonomousContainerDatabaseId The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder autonomousContainerDatabaseId(@Nullable Output<String> autonomousContainerDatabaseId) {
            $.autonomousContainerDatabaseId = autonomousContainerDatabaseId;
            return this;
        }

        /**
         * @param autonomousContainerDatabaseId The Autonomous Container Database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder autonomousContainerDatabaseId(String autonomousContainerDatabaseId) {
            return autonomousContainerDatabaseId(Output.of(autonomousContainerDatabaseId));
        }

        /**
         * @param availabilityDomain The domain of the Autonomous Container Database
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain The domain of the Autonomous Container Database
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param fastStartFailOverLagLimitInSeconds The lag time for my preference based on data loss tolerance in seconds.
         * 
         * @return builder
         * 
         */
        public Builder fastStartFailOverLagLimitInSeconds(@Nullable Output<Integer> fastStartFailOverLagLimitInSeconds) {
            $.fastStartFailOverLagLimitInSeconds = fastStartFailOverLagLimitInSeconds;
            return this;
        }

        /**
         * @param fastStartFailOverLagLimitInSeconds The lag time for my preference based on data loss tolerance in seconds.
         * 
         * @return builder
         * 
         */
        public Builder fastStartFailOverLagLimitInSeconds(Integer fastStartFailOverLagLimitInSeconds) {
            return fastStartFailOverLagLimitInSeconds(Output.of(fastStartFailOverLagLimitInSeconds));
        }

        /**
         * @param isAutomaticFailoverEnabled Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
         * 
         * @return builder
         * 
         */
        public Builder isAutomaticFailoverEnabled(@Nullable Output<Boolean> isAutomaticFailoverEnabled) {
            $.isAutomaticFailoverEnabled = isAutomaticFailoverEnabled;
            return this;
        }

        /**
         * @param isAutomaticFailoverEnabled Indicates whether Automatic Failover is enabled for Autonomous Container Database Dataguard Association
         * 
         * @return builder
         * 
         */
        public Builder isAutomaticFailoverEnabled(Boolean isAutomaticFailoverEnabled) {
            return isAutomaticFailoverEnabled(Output.of(isAutomaticFailoverEnabled));
        }

        /**
         * @param lifecycleDetails Additional information about the current lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(@Nullable Output<String> lifecycleDetails) {
            $.lifecycleDetails = lifecycleDetails;
            return this;
        }

        /**
         * @param lifecycleDetails Additional information about the current lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleDetails(String lifecycleDetails) {
            return lifecycleDetails(Output.of(lifecycleDetails));
        }

        /**
         * @param protectionMode The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
         * 
         * @return builder
         * 
         */
        public Builder protectionMode(@Nullable Output<String> protectionMode) {
            $.protectionMode = protectionMode;
            return this;
        }

        /**
         * @param protectionMode The protection mode of this Autonomous Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
         * 
         * @return builder
         * 
         */
        public Builder protectionMode(String protectionMode) {
            return protectionMode(Output.of(protectionMode));
        }

        /**
         * @param redoTransportMode Automatically selected by backend based on the protection mode.
         * 
         * @return builder
         * 
         */
        public Builder redoTransportMode(@Nullable Output<String> redoTransportMode) {
            $.redoTransportMode = redoTransportMode;
            return this;
        }

        /**
         * @param redoTransportMode Automatically selected by backend based on the protection mode.
         * 
         * @return builder
         * 
         */
        public Builder redoTransportMode(String redoTransportMode) {
            return redoTransportMode(Output.of(redoTransportMode));
        }

        /**
         * @param role The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
         * 
         * @return builder
         * 
         */
        public Builder role(@Nullable Output<String> role) {
            $.role = role;
            return this;
        }

        /**
         * @param role The Data Guard role of the Autonomous Container Database or Autonomous Database, if Autonomous Data Guard is enabled.
         * 
         * @return builder
         * 
         */
        public Builder role(String role) {
            return role(Output.of(role));
        }

        /**
         * @param state The current state of the Autonomous Container Database.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the Autonomous Container Database.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The date and time the Autonomous Container Database was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the Autonomous Container Database was created.
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param timeLagRefreshedOn Timestamp when the lags were last calculated for a standby.
         * 
         * @return builder
         * 
         */
        public Builder timeLagRefreshedOn(@Nullable Output<String> timeLagRefreshedOn) {
            $.timeLagRefreshedOn = timeLagRefreshedOn;
            return this;
        }

        /**
         * @param timeLagRefreshedOn Timestamp when the lags were last calculated for a standby.
         * 
         * @return builder
         * 
         */
        public Builder timeLagRefreshedOn(String timeLagRefreshedOn) {
            return timeLagRefreshedOn(Output.of(timeLagRefreshedOn));
        }

        /**
         * @param timeLastRoleChanged The date and time when the last role change action happened.
         * 
         * @return builder
         * 
         */
        public Builder timeLastRoleChanged(@Nullable Output<String> timeLastRoleChanged) {
            $.timeLastRoleChanged = timeLastRoleChanged;
            return this;
        }

        /**
         * @param timeLastRoleChanged The date and time when the last role change action happened.
         * 
         * @return builder
         * 
         */
        public Builder timeLastRoleChanged(String timeLastRoleChanged) {
            return timeLastRoleChanged(Output.of(timeLastRoleChanged));
        }

        /**
         * @param timeLastSynced The date and time of the last update to the apply lag, apply rate, and transport lag values.
         * 
         * @return builder
         * 
         */
        public Builder timeLastSynced(@Nullable Output<String> timeLastSynced) {
            $.timeLastSynced = timeLastSynced;
            return this;
        }

        /**
         * @param timeLastSynced The date and time of the last update to the apply lag, apply rate, and transport lag values.
         * 
         * @return builder
         * 
         */
        public Builder timeLastSynced(String timeLastSynced) {
            return timeLastSynced(Output.of(timeLastSynced));
        }

        /**
         * @param transportLag The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database. Example: `7 seconds`
         * 
         * @return builder
         * 
         */
        public Builder transportLag(@Nullable Output<String> transportLag) {
            $.transportLag = transportLag;
            return this;
        }

        /**
         * @param transportLag The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database. Example: `7 seconds`
         * 
         * @return builder
         * 
         */
        public Builder transportLag(String transportLag) {
            return transportLag(Output.of(transportLag));
        }

        public AutonomousContainerDatabaseAddStandbyDataguardArgs build() {
            return $;
        }
    }

}
