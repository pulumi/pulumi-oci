// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Outputs
{

    [OutputType]
    public sealed class ConfigConfigurationClientCertificateDetailsPrivateKey
    {
        /// <summary>
        /// (Updatable) Content of the private key file.
        /// </summary>
        public readonly string? Content;
        /// <summary>
        /// (Updatable) Name of the private key file.
        /// </summary>
        public readonly string? FileName;

        [OutputConstructor]
        private ConfigConfigurationClientCertificateDetailsPrivateKey(
            string? content,

            string? fileName)
        {
            Content = content;
            FileName = fileName;
        }
    }
}