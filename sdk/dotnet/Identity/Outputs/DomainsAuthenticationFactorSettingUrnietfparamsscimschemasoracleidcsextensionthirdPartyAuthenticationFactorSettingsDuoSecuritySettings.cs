// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class DomainsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettingsDuoSecuritySettings
    {
        /// <summary>
        /// (Updatable) Hostname to access the Duo security account
        /// </summary>
        public readonly string ApiHostname;
        /// <summary>
        /// (Updatable) Attestation key to attest the request and response between Duo Security
        /// </summary>
        public readonly string? AttestationKey;
        /// <summary>
        /// (Updatable) Integration key from Duo Security authenticator
        /// </summary>
        public readonly string IntegrationKey;
        /// <summary>
        /// (Updatable) Secret key from Duo Security authenticator
        /// </summary>
        public readonly string SecretKey;
        /// <summary>
        /// (Updatable) User attribute mapping value
        /// </summary>
        public readonly string UserMappingAttribute;

        [OutputConstructor]
        private DomainsAuthenticationFactorSettingUrnietfparamsscimschemasoracleidcsextensionthirdPartyAuthenticationFactorSettingsDuoSecuritySettings(
            string apiHostname,

            string? attestationKey,

            string integrationKey,

            string secretKey,

            string userMappingAttribute)
        {
            ApiHostname = apiHostname;
            AttestationKey = attestationKey;
            IntegrationKey = integrationKey;
            SecretKey = secretKey;
            UserMappingAttribute = userMappingAttribute;
        }
    }
}