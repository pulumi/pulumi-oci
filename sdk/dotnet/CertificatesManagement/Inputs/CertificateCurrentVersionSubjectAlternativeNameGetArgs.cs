// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CertificatesManagement.Inputs
{

    public sealed class CertificateCurrentVersionSubjectAlternativeNameGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The subject alternative name type. Currently only DNS domain or host names and IP addresses are supported.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        /// <summary>
        /// The subject alternative name.
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public CertificateCurrentVersionSubjectAlternativeNameGetArgs()
        {
        }
        public static new CertificateCurrentVersionSubjectAlternativeNameGetArgs Empty => new CertificateCurrentVersionSubjectAlternativeNameGetArgs();
    }
}