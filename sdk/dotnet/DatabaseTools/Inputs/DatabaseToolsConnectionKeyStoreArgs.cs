// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseTools.Inputs
{

    public sealed class DatabaseToolsConnectionKeyStoreArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The key store content.
        /// </summary>
        [Input("keyStoreContent")]
        public Input<Inputs.DatabaseToolsConnectionKeyStoreKeyStoreContentArgs>? KeyStoreContent { get; set; }

        /// <summary>
        /// (Updatable) The key store password.
        /// </summary>
        [Input("keyStorePassword")]
        public Input<Inputs.DatabaseToolsConnectionKeyStoreKeyStorePasswordArgs>? KeyStorePassword { get; set; }

        /// <summary>
        /// (Updatable) The key store type.
        /// </summary>
        [Input("keyStoreType")]
        public Input<string>? KeyStoreType { get; set; }

        public DatabaseToolsConnectionKeyStoreArgs()
        {
        }
        public static new DatabaseToolsConnectionKeyStoreArgs Empty => new DatabaseToolsConnectionKeyStoreArgs();
    }
}
