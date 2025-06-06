// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Inputs
{

    public sealed class ConfigConfigurationClientCertificateDetailsClientCertificateGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Content of the client certificate file.
        /// </summary>
        [Input("content")]
        public Input<string>? Content { get; set; }

        /// <summary>
        /// (Updatable) Name of the certificate file. The name should not contain any confidential information.
        /// </summary>
        [Input("fileName")]
        public Input<string>? FileName { get; set; }

        public ConfigConfigurationClientCertificateDetailsClientCertificateGetArgs()
        {
        }
        public static new ConfigConfigurationClientCertificateDetailsClientCertificateGetArgs Empty => new ConfigConfigurationClientCertificateDetailsClientCertificateGetArgs();
    }
}
