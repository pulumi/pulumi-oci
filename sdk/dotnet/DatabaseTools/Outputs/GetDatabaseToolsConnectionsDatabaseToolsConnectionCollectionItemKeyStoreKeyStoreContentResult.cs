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
    public sealed class GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemKeyStoreKeyStoreContentResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the secret containing the user password.
        /// </summary>
        public readonly string SecretId;
        /// <summary>
        /// The value type of the user password.
        /// </summary>
        public readonly string ValueType;

        [OutputConstructor]
        private GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemKeyStoreKeyStoreContentResult(
            string secretId,

            string valueType)
        {
            SecretId = secretId;
            ValueType = valueType;
        }
    }
}
