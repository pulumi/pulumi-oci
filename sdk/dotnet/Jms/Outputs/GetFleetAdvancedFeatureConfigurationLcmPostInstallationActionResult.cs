// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms.Outputs
{

    [OutputType]
    public sealed class GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionResult
    {
        /// <summary>
        /// The following post JRE installation actions are supported by the field:
        /// * Disable TLS 1.0 , TLS 1.1
        /// </summary>
        public readonly ImmutableArray<string> DisabledTlsVersions;
        /// <summary>
        /// test
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingResult> MinimumKeySizeSettings;
        /// <summary>
        /// Restores JDK root certificates with the certificates that are available in the operating system. The following action is supported by the field:
        /// * Replace JDK root certificates with a list provided by the operating system
        /// </summary>
        public readonly bool ShouldReplaceCertificatesOperatingSystem;

        [OutputConstructor]
        private GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionResult(
            ImmutableArray<string> disabledTlsVersions,

            ImmutableArray<Outputs.GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingResult> minimumKeySizeSettings,

            bool shouldReplaceCertificatesOperatingSystem)
        {
            DisabledTlsVersions = disabledTlsVersions;
            MinimumKeySizeSettings = minimumKeySizeSettings;
            ShouldReplaceCertificatesOperatingSystem = shouldReplaceCertificatesOperatingSystem;
        }
    }
}