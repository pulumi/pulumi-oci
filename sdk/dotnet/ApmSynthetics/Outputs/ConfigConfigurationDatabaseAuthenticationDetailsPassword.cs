// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Outputs
{

    [OutputType]
    public sealed class ConfigConfigurationDatabaseAuthenticationDetailsPassword
    {
        /// <summary>
        /// (Updatable) Password.
        /// </summary>
        public readonly string? Password;
        /// <summary>
        /// (Updatable) Type of method to pass password.
        /// </summary>
        public readonly string? PasswordType;
        /// <summary>
        /// (Updatable) Vault secret OCID.
        /// </summary>
        public readonly string? VaultSecretId;

        [OutputConstructor]
        private ConfigConfigurationDatabaseAuthenticationDetailsPassword(
            string? password,

            string? passwordType,

            string? vaultSecretId)
        {
            Password = password;
            PasswordType = passwordType;
            VaultSecretId = vaultSecretId;
        }
    }
}
