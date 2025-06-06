// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseTools.Outputs
{

    [OutputType]
    public sealed class DatabaseToolsConnectionKeyStoreKeyStoreContent
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the key store.
        /// </summary>
        public readonly string? SecretId;
        /// <summary>
        /// (Updatable) The value type of the key store content.
        /// </summary>
        public readonly string ValueType;

        [OutputConstructor]
        private DatabaseToolsConnectionKeyStoreKeyStoreContent(
            string? secretId,

            string valueType)
        {
            SecretId = secretId;
            ValueType = valueType;
        }
    }
}
