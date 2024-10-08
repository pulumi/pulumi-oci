// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Jms.outputs.GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingCertpath;
import com.pulumi.oci.Jms.outputs.GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingJar;
import com.pulumi.oci.Jms.outputs.GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingTl;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSetting {
    /**
     * @return Updates the minimum key size for the specified encryption algorithm. The JDK property jdk.certpath.disabledAlgorithms will be updated with the following supported actions:
     * * Changing minimum key length for RSA signed jars
     * * Changing minimum key length for EC
     * * Changing minimum key length for DSA
     * 
     */
    private List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingCertpath> certpaths;
    /**
     * @return Updates the minimum key size for the specified encryption algorithm. The JDK property jdk.jar.disabledAlgorithms will be updated with the following supported actions:
     * * Changing minimum key length for RSA signed jars
     * * Changing minimum key length for EC
     * * Changing minimum key length for DSA
     * 
     */
    private List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingJar> jars;
    /**
     * @return Updates the minimum key size for the specified encryption algorithm. The JDK property jdk.tls.disabledAlgorithms will be updated with the following supported actions:
     * * Changing minimum key length for Diffie-Hellman
     * 
     */
    private List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingTl> tls;

    private GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSetting() {}
    /**
     * @return Updates the minimum key size for the specified encryption algorithm. The JDK property jdk.certpath.disabledAlgorithms will be updated with the following supported actions:
     * * Changing minimum key length for RSA signed jars
     * * Changing minimum key length for EC
     * * Changing minimum key length for DSA
     * 
     */
    public List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingCertpath> certpaths() {
        return this.certpaths;
    }
    /**
     * @return Updates the minimum key size for the specified encryption algorithm. The JDK property jdk.jar.disabledAlgorithms will be updated with the following supported actions:
     * * Changing minimum key length for RSA signed jars
     * * Changing minimum key length for EC
     * * Changing minimum key length for DSA
     * 
     */
    public List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingJar> jars() {
        return this.jars;
    }
    /**
     * @return Updates the minimum key size for the specified encryption algorithm. The JDK property jdk.tls.disabledAlgorithms will be updated with the following supported actions:
     * * Changing minimum key length for Diffie-Hellman
     * 
     */
    public List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingTl> tls() {
        return this.tls;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSetting defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingCertpath> certpaths;
        private List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingJar> jars;
        private List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingTl> tls;
        public Builder() {}
        public Builder(GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSetting defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.certpaths = defaults.certpaths;
    	      this.jars = defaults.jars;
    	      this.tls = defaults.tls;
        }

        @CustomType.Setter
        public Builder certpaths(List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingCertpath> certpaths) {
            if (certpaths == null) {
              throw new MissingRequiredPropertyException("GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSetting", "certpaths");
            }
            this.certpaths = certpaths;
            return this;
        }
        public Builder certpaths(GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingCertpath... certpaths) {
            return certpaths(List.of(certpaths));
        }
        @CustomType.Setter
        public Builder jars(List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingJar> jars) {
            if (jars == null) {
              throw new MissingRequiredPropertyException("GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSetting", "jars");
            }
            this.jars = jars;
            return this;
        }
        public Builder jars(GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingJar... jars) {
            return jars(List.of(jars));
        }
        @CustomType.Setter
        public Builder tls(List<GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingTl> tls) {
            if (tls == null) {
              throw new MissingRequiredPropertyException("GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSetting", "tls");
            }
            this.tls = tls;
            return this;
        }
        public Builder tls(GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingTl... tls) {
            return tls(List.of(tls));
        }
        public GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSetting build() {
            final var _resultValue = new GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSetting();
            _resultValue.certpaths = certpaths;
            _resultValue.jars = jars;
            _resultValue.tls = tls;
            return _resultValue;
        }
    }
}
