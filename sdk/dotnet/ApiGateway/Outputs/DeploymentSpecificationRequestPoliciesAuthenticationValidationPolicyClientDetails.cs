// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Outputs
{

    [OutputType]
    public sealed class DeploymentSpecificationRequestPoliciesAuthenticationValidationPolicyClientDetails
    {
        /// <summary>
        /// (Updatable) Client ID for the OAuth2/OIDC app.
        /// </summary>
        public readonly string? ClientId;
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Vault Service secret resource.
        /// </summary>
        public readonly string? ClientSecretId;
        /// <summary>
        /// (Updatable) The version number of the client secret to use.
        /// </summary>
        public readonly string? ClientSecretVersionNumber;
        /// <summary>
        /// (Updatable) Type of the Response Cache Store Policy.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private DeploymentSpecificationRequestPoliciesAuthenticationValidationPolicyClientDetails(
            string? clientId,

            string? clientSecretId,

            string? clientSecretVersionNumber,

            string type)
        {
            ClientId = clientId;
            ClientSecretId = clientSecretId;
            ClientSecretVersionNumber = clientSecretVersionNumber;
            Type = type;
        }
    }
}