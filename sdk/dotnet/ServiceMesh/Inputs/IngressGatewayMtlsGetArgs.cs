// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ServiceMesh.Inputs
{

    public sealed class IngressGatewayMtlsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the leaf certificate resource.
        /// </summary>
        [Input("certificateId")]
        public Input<string>? CertificateId { get; set; }

        /// <summary>
        /// (Updatable) The number of days the mTLS certificate is valid.  This value should be less than the Maximum Validity Duration  for Certificates (Days) setting on the Certificate Authority associated with this Mesh.  The certificate will be automatically renewed after 2/3 of the validity period, so a certificate with a maximum validity of 45 days will be renewed every 30 days.
        /// </summary>
        [Input("maximumValidity")]
        public Input<int>? MaximumValidity { get; set; }

        public IngressGatewayMtlsGetArgs()
        {
        }
        public static new IngressGatewayMtlsGetArgs Empty => new IngressGatewayMtlsGetArgs();
    }
}