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
    public sealed class GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionProxyResult
    {
        /// <summary>
        /// Ftp host to be set in net.properties file.
        /// </summary>
        public readonly string FtpProxyHost;
        /// <summary>
        /// Ftp port number to be set in net.properties file.
        /// </summary>
        public readonly int FtpProxyPort;
        /// <summary>
        /// Http host to be set in net.properties file.
        /// </summary>
        public readonly string HttpProxyHost;
        /// <summary>
        /// Http port number to be set in net.properties file.
        /// </summary>
        public readonly int HttpProxyPort;
        /// <summary>
        /// Https host to be set in net.properties file.
        /// </summary>
        public readonly string HttpsProxyHost;
        /// <summary>
        /// Https port number to be set in net.properties file.
        /// </summary>
        public readonly int HttpsProxyPort;
        /// <summary>
        /// Socks host to be set in net.properties file.
        /// </summary>
        public readonly string SocksProxyHost;
        /// <summary>
        /// Socks port number to be set in net.properties file.
        /// </summary>
        public readonly int SocksProxyPort;
        /// <summary>
        /// Sets "java.net.useSystemProxies=true" in net.properties when they exist.
        /// </summary>
        public readonly bool UseSystemProxies;

        [OutputConstructor]
        private GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionProxyResult(
            string ftpProxyHost,

            int ftpProxyPort,

            string httpProxyHost,

            int httpProxyPort,

            string httpsProxyHost,

            int httpsProxyPort,

            string socksProxyHost,

            int socksProxyPort,

            bool useSystemProxies)
        {
            FtpProxyHost = ftpProxyHost;
            FtpProxyPort = ftpProxyPort;
            HttpProxyHost = httpProxyHost;
            HttpProxyPort = httpProxyPort;
            HttpsProxyHost = httpsProxyHost;
            HttpsProxyPort = httpsProxyPort;
            SocksProxyHost = socksProxyHost;
            SocksProxyPort = socksProxyPort;
            UseSystemProxies = useSystemProxies;
        }
    }
}