// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Inputs
{

    public sealed class ConfigConfigurationClientCertificateDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Client certificate in PEM format.
        /// </summary>
        [Input("clientCertificate")]
        public Input<Inputs.ConfigConfigurationClientCertificateDetailsClientCertificateGetArgs>? ClientCertificate { get; set; }

        /// <summary>
        /// (Updatable) The private key associated with the client certificate in PEM format.
        /// </summary>
        [Input("privateKey")]
        public Input<Inputs.ConfigConfigurationClientCertificateDetailsPrivateKeyGetArgs>? PrivateKey { get; set; }

        public ConfigConfigurationClientCertificateDetailsGetArgs()
        {
        }
        public static new ConfigConfigurationClientCertificateDetailsGetArgs Empty => new ConfigConfigurationClientCertificateDetailsGetArgs();
    }
}
