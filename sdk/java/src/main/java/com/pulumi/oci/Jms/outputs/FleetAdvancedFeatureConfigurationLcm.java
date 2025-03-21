// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Jms.outputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActions;
import java.lang.Boolean;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class FleetAdvancedFeatureConfigurationLcm {
    /**
     * @return (Updatable) Lifecycle management flag to store enabled or disabled status.
     * 
     */
    private @Nullable Boolean isEnabled;
    /**
     * @return (Updatable) List of available post actions you can execute after the successful Java installation.
     * 
     */
    private @Nullable FleetAdvancedFeatureConfigurationLcmPostInstallationActions postInstallationActions;

    private FleetAdvancedFeatureConfigurationLcm() {}
    /**
     * @return (Updatable) Lifecycle management flag to store enabled or disabled status.
     * 
     */
    public Optional<Boolean> isEnabled() {
        return Optional.ofNullable(this.isEnabled);
    }
    /**
     * @return (Updatable) List of available post actions you can execute after the successful Java installation.
     * 
     */
    public Optional<FleetAdvancedFeatureConfigurationLcmPostInstallationActions> postInstallationActions() {
        return Optional.ofNullable(this.postInstallationActions);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(FleetAdvancedFeatureConfigurationLcm defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean isEnabled;
        private @Nullable FleetAdvancedFeatureConfigurationLcmPostInstallationActions postInstallationActions;
        public Builder() {}
        public Builder(FleetAdvancedFeatureConfigurationLcm defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isEnabled = defaults.isEnabled;
    	      this.postInstallationActions = defaults.postInstallationActions;
        }

        @CustomType.Setter
        public Builder isEnabled(@Nullable Boolean isEnabled) {

            this.isEnabled = isEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder postInstallationActions(@Nullable FleetAdvancedFeatureConfigurationLcmPostInstallationActions postInstallationActions) {

            this.postInstallationActions = postInstallationActions;
            return this;
        }
        public FleetAdvancedFeatureConfigurationLcm build() {
            final var _resultValue = new FleetAdvancedFeatureConfigurationLcm();
            _resultValue.isEnabled = isEnabled;
            _resultValue.postInstallationActions = postInstallationActions;
            return _resultValue;
        }
    }
}
