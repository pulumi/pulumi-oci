// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Outputs
{

    [OutputType]
    public sealed class GetMonitoredResourceCredentialResult
    {
        /// <summary>
        /// Type of credentials specified in the credentials element. Three possible values - EXISTING, PLAINTEXT and ENCRYPTED. * EXISTING  - Credential is already stored in agent and only credential name need to be passed for existing credential. * PLAINTEXT - The credential properties will have credentials in plain text format. * ENCRYPTED - The credential properties will have credentials stored in vault in encrypted format using KMS client which uses master key for encryption. The same master key will be used to decrypt the credentials before passing on to the management agent.
        /// </summary>
        public readonly string CredentialType;
        /// <summary>
        /// The user-specified textual description of the credential.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The master key OCID and applicable only for property value type ENCRYPTION. Key OCID is passed as input to Key management service decrypt API to retrieve the encrypted property value text.
        /// </summary>
        public readonly string KeyId;
        /// <summary>
        /// property name
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// List of monitored resource properties
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMonitoredResourceCredentialPropertyResult> Properties;
        /// <summary>
        /// The source type and source name combination,delimited with (.) separator. {source type}.{source name} and source type max char limit is 63.
        /// </summary>
        public readonly string Source;
        /// <summary>
        /// Monitored resource type
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetMonitoredResourceCredentialResult(
            string credentialType,

            string description,

            string keyId,

            string name,

            ImmutableArray<Outputs.GetMonitoredResourceCredentialPropertyResult> properties,

            string source,

            string type)
        {
            CredentialType = credentialType;
            Description = description;
            KeyId = keyId;
            Name = name;
            Properties = properties;
            Source = source;
            Type = type;
        }
    }
}