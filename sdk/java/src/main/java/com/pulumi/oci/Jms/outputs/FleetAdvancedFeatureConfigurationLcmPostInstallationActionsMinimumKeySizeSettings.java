// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Jms.outputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsCertpath;
import com.pulumi.oci.Jms.outputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsJar;
import com.pulumi.oci.Jms.outputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTl;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettings {
    /**
     * @return (Updatable) Updates the minimum key size for the specified encryption algorithm. The JDK property jdk.certpath.disabledAlgorithms will be updated with the following supported actions:
     * * Changing minimum key length for RSA signed jars
     * * Changing minimum key length for EC
     * * Changing minimum key length for DSA
     * 
     */
    private @Nullable List<FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsCertpath> certpaths;
    /**
     * @return (Updatable) Updates the minimum key size for the specified encryption algorithm. The JDK property jdk.jar.disabledAlgorithms will be updated with the following supported actions:
     * * Changing minimum key length for RSA signed jars
     * * Changing minimum key length for EC
     * * Changing minimum key length for DSA
     * 
     */
    private @Nullable List<FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsJar> jars;
    /**
     * @return (Updatable) Updates the minimum key size for the specified encryption algorithm. The JDK property jdk.tls.disabledAlgorithms will be updated with the following supported actions:
     * * Changing minimum key length for Diffie-Hellman
     * 
     */
    private @Nullable List<FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTl> tls;

    private FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettings() {}
    /**
     * @return (Updatable) Updates the minimum key size for the specified encryption algorithm. The JDK property jdk.certpath.disabledAlgorithms will be updated with the following supported actions:
     * * Changing minimum key length for RSA signed jars
     * * Changing minimum key length for EC
     * * Changing minimum key length for DSA
     * 
     */
    public List<FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsCertpath> certpaths() {
        return this.certpaths == null ? List.of() : this.certpaths;
    }
    /**
     * @return (Updatable) Updates the minimum key size for the specified encryption algorithm. The JDK property jdk.jar.disabledAlgorithms will be updated with the following supported actions:
     * * Changing minimum key length for RSA signed jars
     * * Changing minimum key length for EC
     * * Changing minimum key length for DSA
     * 
     */
    public List<FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsJar> jars() {
        return this.jars == null ? List.of() : this.jars;
    }
    /**
     * @return (Updatable) Updates the minimum key size for the specified encryption algorithm. The JDK property jdk.tls.disabledAlgorithms will be updated with the following supported actions:
     * * Changing minimum key length for Diffie-Hellman
     * 
     */
    public List<FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTl> tls() {
        return this.tls == null ? List.of() : this.tls;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettings defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsCertpath> certpaths;
        private @Nullable List<FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsJar> jars;
        private @Nullable List<FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTl> tls;
        public Builder() {}
        public Builder(FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettings defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.certpaths = defaults.certpaths;
    	      this.jars = defaults.jars;
    	      this.tls = defaults.tls;
        }

        @CustomType.Setter
        public Builder certpaths(@Nullable List<FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsCertpath> certpaths) {

            this.certpaths = certpaths;
            return this;
        }
        public Builder certpaths(FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsCertpath... certpaths) {
            return certpaths(List.of(certpaths));
        }
        @CustomType.Setter
        public Builder jars(@Nullable List<FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsJar> jars) {

            this.jars = jars;
            return this;
        }
        public Builder jars(FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsJar... jars) {
            return jars(List.of(jars));
        }
        @CustomType.Setter
        public Builder tls(@Nullable List<FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTl> tls) {

            this.tls = tls;
            return this;
        }
        public Builder tls(FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTl... tls) {
            return tls(List.of(tls));
        }
        public FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettings build() {
            final var _resultValue = new FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettings();
            _resultValue.certpaths = certpaths;
            _resultValue.jars = jars;
            _resultValue.tls = tls;
            return _resultValue;
        }
    }
}
