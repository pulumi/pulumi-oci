// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs extends com.pulumi.resources.ResourceArgs {

    public static final AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs Empty = new AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs();

    /**
     * Indicates the disaster recovery (DR) type of the Shared Autonomous Database. Autonomous Data Guard (ADG) DR type provides business critical DR with a faster recovery time objective (RTO) during failover or switchover. Backup-based DR type provides lower cost DR with a slower RTO during failover or switchover.
     * 
     */
    @Import(name="disasterRecoveryType")
    private @Nullable Output<String> disasterRecoveryType;

    /**
     * @return Indicates the disaster recovery (DR) type of the Shared Autonomous Database. Autonomous Data Guard (ADG) DR type provides business critical DR with a faster recovery time objective (RTO) during failover or switchover. Backup-based DR type provides lower cost DR with a slower RTO during failover or switchover.
     * 
     */
    public Optional<Output<String>> disasterRecoveryType() {
        return Optional.ofNullable(this.disasterRecoveryType);
    }

    private AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs() {}

    private AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs(AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs $) {
        this.disasterRecoveryType = $.disasterRecoveryType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs $;

        public Builder() {
            $ = new AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs();
        }

        public Builder(AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs defaults) {
            $ = new AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param disasterRecoveryType Indicates the disaster recovery (DR) type of the Shared Autonomous Database. Autonomous Data Guard (ADG) DR type provides business critical DR with a faster recovery time objective (RTO) during failover or switchover. Backup-based DR type provides lower cost DR with a slower RTO during failover or switchover.
         * 
         * @return builder
         * 
         */
        public Builder disasterRecoveryType(@Nullable Output<String> disasterRecoveryType) {
            $.disasterRecoveryType = disasterRecoveryType;
            return this;
        }

        /**
         * @param disasterRecoveryType Indicates the disaster recovery (DR) type of the Shared Autonomous Database. Autonomous Data Guard (ADG) DR type provides business critical DR with a faster recovery time objective (RTO) during failover or switchover. Backup-based DR type provides lower cost DR with a slower RTO during failover or switchover.
         * 
         * @return builder
         * 
         */
        public Builder disasterRecoveryType(String disasterRecoveryType) {
            return disasterRecoveryType(Output.of(disasterRecoveryType));
        }

        public AutonomousDatabaseRemoteDisasterRecoveryConfigurationArgs build() {
            return $;
        }
    }

}