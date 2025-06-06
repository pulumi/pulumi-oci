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
    public sealed class GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemKeyStoreResult
    {
        /// <summary>
        /// The key store content.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemKeyStoreKeyStoreContentResult> KeyStoreContents;
        /// <summary>
        /// The key store password.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemKeyStoreKeyStorePasswordResult> KeyStorePasswords;
        /// <summary>
        /// The key store type.
        /// </summary>
        public readonly string KeyStoreType;

        [OutputConstructor]
        private GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemKeyStoreResult(
            ImmutableArray<Outputs.GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemKeyStoreKeyStoreContentResult> keyStoreContents,

            ImmutableArray<Outputs.GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItemKeyStoreKeyStorePasswordResult> keyStorePasswords,

            string keyStoreType)
        {
            KeyStoreContents = keyStoreContents;
            KeyStorePasswords = keyStorePasswords;
            KeyStoreType = keyStoreType;
        }
    }
}
