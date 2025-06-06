// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms.Outputs
{

    [OutputType]
    public sealed class FleetAdvancedFeatureConfigurationLcmPostInstallationActions
    {
        /// <summary>
        /// (Updatable) Sets FileHandler and ConsoleHandler as handlers in logging.properties file.
        /// </summary>
        public readonly bool? AddLoggingHandler;
        /// <summary>
        /// (Updatable) The following post JRE installation actions are supported by the field:
        /// * Disable TLS 1.0 , TLS 1.1
        /// </summary>
        public readonly ImmutableArray<string> DisabledTlsVersions;
        /// <summary>
        /// (Updatable) Sets the logging level in logging.properties file.
        /// </summary>
        public readonly string? GlobalLoggingLevel;
        /// <summary>
        /// (Updatable) test
        /// </summary>
        public readonly Outputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettings? MinimumKeySizeSettings;
        /// <summary>
        /// (Updatable) List of proxy properties to be configured in net.properties file.
        /// </summary>
        public readonly Outputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsProxies? Proxies;
        /// <summary>
        /// (Updatable) Restores JDK root certificates with the certificates that are available in the operating system. The following action is supported by the field:
        /// * Replace JDK root certificates with a list provided by the operating system.
        /// </summary>
        public readonly bool? ShouldReplaceCertificatesOperatingSystem;

        [OutputConstructor]
        private FleetAdvancedFeatureConfigurationLcmPostInstallationActions(
            bool? addLoggingHandler,

            ImmutableArray<string> disabledTlsVersions,

            string? globalLoggingLevel,

            Outputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsMinimumKeySizeSettings? minimumKeySizeSettings,

            Outputs.FleetAdvancedFeatureConfigurationLcmPostInstallationActionsProxies? proxies,

            bool? shouldReplaceCertificatesOperatingSystem)
        {
            AddLoggingHandler = addLoggingHandler;
            DisabledTlsVersions = disabledTlsVersions;
            GlobalLoggingLevel = globalLoggingLevel;
            MinimumKeySizeSettings = minimumKeySizeSettings;
            Proxies = proxies;
            ShouldReplaceCertificatesOperatingSystem = shouldReplaceCertificatesOperatingSystem;
        }
    }
}
