// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms.Inputs
{

    public sealed class FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("certpaths")]
        private InputList<Inputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsCertpathGetArgs>? _certpaths;

        /// <summary>
        /// (Updatable) Updates the minimum key size for the specified encryption algorithm. The JDK property jdk.certpath.disabledAlgorithms will be updated with the following supported actions:
        /// * Changing minimum key length for RSA signed jars
        /// * Changing minimum key length for EC
        /// * Changing minimum key length for DSA
        /// </summary>
        public InputList<Inputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsCertpathGetArgs> Certpaths
        {
            get => _certpaths ?? (_certpaths = new InputList<Inputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsCertpathGetArgs>());
            set => _certpaths = value;
        }

        [Input("jars")]
        private InputList<Inputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsJarGetArgs>? _jars;

        /// <summary>
        /// (Updatable) Updates the minimum key size for the specified encryption algorithm. The JDK property jdk.jar.disabledAlgorithms will be updated with the following supported actions:
        /// * Changing minimum key length for RSA signed jars
        /// * Changing minimum key length for EC
        /// * Changing minimum key length for DSA
        /// </summary>
        public InputList<Inputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsJarGetArgs> Jars
        {
            get => _jars ?? (_jars = new InputList<Inputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsJarGetArgs>());
            set => _jars = value;
        }

        [Input("tls")]
        private InputList<Inputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlGetArgs>? _tls;

        /// <summary>
        /// (Updatable) Updates the minimum key size for the specified encryption algorithm. The JDK property jdk.tls.disabledAlgorithms will be updated with the following supported actions:
        /// * Changing minimum key length for Diffie-Hellman
        /// </summary>
        public InputList<Inputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlGetArgs> Tls
        {
            get => _tls ?? (_tls = new InputList<Inputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsTlGetArgs>());
            set => _tls = value;
        }

        public FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsGetArgs()
        {
        }
        public static new FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsGetArgs Empty => new FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettingsGetArgs();
    }
}
