// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Inputs
{

    public sealed class ExternalExadataStorageConnectorCredentialInfoArgs : global::Pulumi.ResourceArgs
    {
        [Input("password", required: true)]
        private Input<string>? _password;

        /// <summary>
        /// (Updatable) The password of the user.
        /// </summary>
        public Input<string>? Password
        {
            get => _password;
            set
            {
                var emptySecret = Output.CreateSecret(0);
                _password = Output.Tuple<Input<string>?, int>(value, emptySecret).Apply(t => t.Item1);
            }
        }

        /// <summary>
        /// (Updatable) The full path of the SSL truststore location in the agent.
        /// </summary>
        [Input("sslTrustStoreLocation")]
        public Input<string>? SslTrustStoreLocation { get; set; }

        [Input("sslTrustStorePassword")]
        private Input<string>? _sslTrustStorePassword;

        /// <summary>
        /// (Updatable) The password of the SSL truststore location in the agent.
        /// </summary>
        public Input<string>? SslTrustStorePassword
        {
            get => _sslTrustStorePassword;
            set
            {
                var emptySecret = Output.CreateSecret(0);
                _sslTrustStorePassword = Output.Tuple<Input<string>?, int>(value, emptySecret).Apply(t => t.Item1);
            }
        }

        /// <summary>
        /// (Updatable) The SSL truststore type.
        /// </summary>
        [Input("sslTrustStoreType")]
        public Input<string>? SslTrustStoreType { get; set; }

        /// <summary>
        /// (Updatable) The name of the user.
        /// </summary>
        [Input("username", required: true)]
        public Input<string> Username { get; set; } = null!;

        public ExternalExadataStorageConnectorCredentialInfoArgs()
        {
        }
        public static new ExternalExadataStorageConnectorCredentialInfoArgs Empty => new ExternalExadataStorageConnectorCredentialInfoArgs();
    }
}
