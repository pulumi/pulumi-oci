// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ExadataInfrastructureNetworkBondingModeDetails {
    /**
     * @return (Updatable) The network bonding mode for the Exadata infrastructure.
     * 
     */
    private @Nullable String backupNetworkBondingMode;
    /**
     * @return (Updatable) The network bonding mode for the Exadata infrastructure.
     * 
     */
    private @Nullable String clientNetworkBondingMode;
    /**
     * @return (Updatable) The network bonding mode for the Exadata infrastructure.
     * 
     */
    private @Nullable String drNetworkBondingMode;

    private ExadataInfrastructureNetworkBondingModeDetails() {}
    /**
     * @return (Updatable) The network bonding mode for the Exadata infrastructure.
     * 
     */
    public Optional<String> backupNetworkBondingMode() {
        return Optional.ofNullable(this.backupNetworkBondingMode);
    }
    /**
     * @return (Updatable) The network bonding mode for the Exadata infrastructure.
     * 
     */
    public Optional<String> clientNetworkBondingMode() {
        return Optional.ofNullable(this.clientNetworkBondingMode);
    }
    /**
     * @return (Updatable) The network bonding mode for the Exadata infrastructure.
     * 
     */
    public Optional<String> drNetworkBondingMode() {
        return Optional.ofNullable(this.drNetworkBondingMode);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ExadataInfrastructureNetworkBondingModeDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String backupNetworkBondingMode;
        private @Nullable String clientNetworkBondingMode;
        private @Nullable String drNetworkBondingMode;
        public Builder() {}
        public Builder(ExadataInfrastructureNetworkBondingModeDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.backupNetworkBondingMode = defaults.backupNetworkBondingMode;
    	      this.clientNetworkBondingMode = defaults.clientNetworkBondingMode;
    	      this.drNetworkBondingMode = defaults.drNetworkBondingMode;
        }

        @CustomType.Setter
        public Builder backupNetworkBondingMode(@Nullable String backupNetworkBondingMode) {

            this.backupNetworkBondingMode = backupNetworkBondingMode;
            return this;
        }
        @CustomType.Setter
        public Builder clientNetworkBondingMode(@Nullable String clientNetworkBondingMode) {

            this.clientNetworkBondingMode = clientNetworkBondingMode;
            return this;
        }
        @CustomType.Setter
        public Builder drNetworkBondingMode(@Nullable String drNetworkBondingMode) {

            this.drNetworkBondingMode = drNetworkBondingMode;
            return this;
        }
        public ExadataInfrastructureNetworkBondingModeDetails build() {
            final var _resultValue = new ExadataInfrastructureNetworkBondingModeDetails();
            _resultValue.backupNetworkBondingMode = backupNetworkBondingMode;
            _resultValue.clientNetworkBondingMode = clientNetworkBondingMode;
            _resultValue.drNetworkBondingMode = drNetworkBondingMode;
            return _resultValue;
        }
    }
}
