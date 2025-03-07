// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExadataInfrastructureNetworkBondingModeDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final ExadataInfrastructureNetworkBondingModeDetailsArgs Empty = new ExadataInfrastructureNetworkBondingModeDetailsArgs();

    /**
     * (Updatable) The network bonding mode for the Exadata infrastructure.
     * 
     */
    @Import(name="backupNetworkBondingMode")
    private @Nullable Output<String> backupNetworkBondingMode;

    /**
     * @return (Updatable) The network bonding mode for the Exadata infrastructure.
     * 
     */
    public Optional<Output<String>> backupNetworkBondingMode() {
        return Optional.ofNullable(this.backupNetworkBondingMode);
    }

    /**
     * (Updatable) The network bonding mode for the Exadata infrastructure.
     * 
     */
    @Import(name="clientNetworkBondingMode")
    private @Nullable Output<String> clientNetworkBondingMode;

    /**
     * @return (Updatable) The network bonding mode for the Exadata infrastructure.
     * 
     */
    public Optional<Output<String>> clientNetworkBondingMode() {
        return Optional.ofNullable(this.clientNetworkBondingMode);
    }

    /**
     * (Updatable) The network bonding mode for the Exadata infrastructure.
     * 
     */
    @Import(name="drNetworkBondingMode")
    private @Nullable Output<String> drNetworkBondingMode;

    /**
     * @return (Updatable) The network bonding mode for the Exadata infrastructure.
     * 
     */
    public Optional<Output<String>> drNetworkBondingMode() {
        return Optional.ofNullable(this.drNetworkBondingMode);
    }

    private ExadataInfrastructureNetworkBondingModeDetailsArgs() {}

    private ExadataInfrastructureNetworkBondingModeDetailsArgs(ExadataInfrastructureNetworkBondingModeDetailsArgs $) {
        this.backupNetworkBondingMode = $.backupNetworkBondingMode;
        this.clientNetworkBondingMode = $.clientNetworkBondingMode;
        this.drNetworkBondingMode = $.drNetworkBondingMode;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExadataInfrastructureNetworkBondingModeDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExadataInfrastructureNetworkBondingModeDetailsArgs $;

        public Builder() {
            $ = new ExadataInfrastructureNetworkBondingModeDetailsArgs();
        }

        public Builder(ExadataInfrastructureNetworkBondingModeDetailsArgs defaults) {
            $ = new ExadataInfrastructureNetworkBondingModeDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param backupNetworkBondingMode (Updatable) The network bonding mode for the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder backupNetworkBondingMode(@Nullable Output<String> backupNetworkBondingMode) {
            $.backupNetworkBondingMode = backupNetworkBondingMode;
            return this;
        }

        /**
         * @param backupNetworkBondingMode (Updatable) The network bonding mode for the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder backupNetworkBondingMode(String backupNetworkBondingMode) {
            return backupNetworkBondingMode(Output.of(backupNetworkBondingMode));
        }

        /**
         * @param clientNetworkBondingMode (Updatable) The network bonding mode for the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder clientNetworkBondingMode(@Nullable Output<String> clientNetworkBondingMode) {
            $.clientNetworkBondingMode = clientNetworkBondingMode;
            return this;
        }

        /**
         * @param clientNetworkBondingMode (Updatable) The network bonding mode for the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder clientNetworkBondingMode(String clientNetworkBondingMode) {
            return clientNetworkBondingMode(Output.of(clientNetworkBondingMode));
        }

        /**
         * @param drNetworkBondingMode (Updatable) The network bonding mode for the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder drNetworkBondingMode(@Nullable Output<String> drNetworkBondingMode) {
            $.drNetworkBondingMode = drNetworkBondingMode;
            return this;
        }

        /**
         * @param drNetworkBondingMode (Updatable) The network bonding mode for the Exadata infrastructure.
         * 
         * @return builder
         * 
         */
        public Builder drNetworkBondingMode(String drNetworkBondingMode) {
            return drNetworkBondingMode(Output.of(drNetworkBondingMode));
        }

        public ExadataInfrastructureNetworkBondingModeDetailsArgs build() {
            return $;
        }
    }

}
