// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRequestPoliciesMutualTlsGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("allowedSans")]
        private InputList<string>? _allowedSans;

        /// <summary>
        /// (Updatable) Allowed list of CN or SAN which will be used for verification of certificate.
        /// </summary>
        public InputList<string> AllowedSans
        {
            get => _allowedSans ?? (_allowedSans = new InputList<string>());
            set => _allowedSans = value;
        }

        /// <summary>
        /// (Updatable) Determines whether to enable client verification when API Consumer makes connection to the gateway.
        /// </summary>
        [Input("isVerifiedCertificateRequired")]
        public Input<bool>? IsVerifiedCertificateRequired { get; set; }

        public DeploymentSpecificationRequestPoliciesMutualTlsGetArgs()
        {
        }
        public static new DeploymentSpecificationRequestPoliciesMutualTlsGetArgs Empty => new DeploymentSpecificationRequestPoliciesMutualTlsGetArgs();
    }
}