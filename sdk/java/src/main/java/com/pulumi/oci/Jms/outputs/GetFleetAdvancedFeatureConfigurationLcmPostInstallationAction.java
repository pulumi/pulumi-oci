// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Jms.outputs.GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSetting;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetFleetAdvancedFeatureConfigurationLcmPostInstallationAction {
    /**
     * @return The following post JRE installation actions are supported by the field:
     * * Disable TLS 1.0 , TLS 1.1
     * 
     */
    private List<String> disabledTlsVersions;
    /**
     * @return test
     * 
     */
    private List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSetting> minimumKeySizeSettings;
    /**
     * @return Restores JDK root certificates with the certificates that are available in the operating system. The following action is supported by the field:
     * * Replace JDK root certificates with a list provided by the operating system
     * 
     */
    private Boolean shouldReplaceCertificatesOperatingSystem;

    private GetFleetAdvancedFeatureConfigurationLcmPostInstallationAction() {}
    /**
     * @return The following post JRE installation actions are supported by the field:
     * * Disable TLS 1.0 , TLS 1.1
     * 
     */
    public List<String> disabledTlsVersions() {
        return this.disabledTlsVersions;
    }
    /**
     * @return test
     * 
     */
    public List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSetting> minimumKeySizeSettings() {
        return this.minimumKeySizeSettings;
    }
    /**
     * @return Restores JDK root certificates with the certificates that are available in the operating system. The following action is supported by the field:
     * * Replace JDK root certificates with a list provided by the operating system
     * 
     */
    public Boolean shouldReplaceCertificatesOperatingSystem() {
        return this.shouldReplaceCertificatesOperatingSystem;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFleetAdvancedFeatureConfigurationLcmPostInstallationAction defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> disabledTlsVersions;
        private List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSetting> minimumKeySizeSettings;
        private Boolean shouldReplaceCertificatesOperatingSystem;
        public Builder() {}
        public Builder(GetFleetAdvancedFeatureConfigurationLcmPostInstallationAction defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.disabledTlsVersions = defaults.disabledTlsVersions;
    	      this.minimumKeySizeSettings = defaults.minimumKeySizeSettings;
    	      this.shouldReplaceCertificatesOperatingSystem = defaults.shouldReplaceCertificatesOperatingSystem;
        }

        @CustomType.Setter
        public Builder disabledTlsVersions(List<String> disabledTlsVersions) {
            this.disabledTlsVersions = Objects.requireNonNull(disabledTlsVersions);
            return this;
        }
        public Builder disabledTlsVersions(String... disabledTlsVersions) {
            return disabledTlsVersions(List.of(disabledTlsVersions));
        }
        @CustomType.Setter
        public Builder minimumKeySizeSettings(List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSetting> minimumKeySizeSettings) {
            this.minimumKeySizeSettings = Objects.requireNonNull(minimumKeySizeSettings);
            return this;
        }
        public Builder minimumKeySizeSettings(GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSetting... minimumKeySizeSettings) {
            return minimumKeySizeSettings(List.of(minimumKeySizeSettings));
        }
        @CustomType.Setter
        public Builder shouldReplaceCertificatesOperatingSystem(Boolean shouldReplaceCertificatesOperatingSystem) {
            this.shouldReplaceCertificatesOperatingSystem = Objects.requireNonNull(shouldReplaceCertificatesOperatingSystem);
            return this;
        }
        public GetFleetAdvancedFeatureConfigurationLcmPostInstallationAction build() {
            final var o = new GetFleetAdvancedFeatureConfigurationLcmPostInstallationAction();
            o.disabledTlsVersions = disabledTlsVersions;
            o.minimumKeySizeSettings = minimumKeySizeSettings;
            o.shouldReplaceCertificatesOperatingSystem = shouldReplaceCertificatesOperatingSystem;
            return o;
        }
    }
}