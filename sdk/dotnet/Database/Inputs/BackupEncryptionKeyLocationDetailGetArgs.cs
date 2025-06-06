// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class BackupEncryptionKeyLocationDetailGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("hsmPassword")]
        private Input<string>? _hsmPassword;

        /// <summary>
        /// Provide the HSM password as you would in RDBMS for External HSM.
        /// </summary>
        public Input<string>? HsmPassword
        {
            get => _hsmPassword;
            set
            {
                var emptySecret = Output.CreateSecret(0);
                _hsmPassword = Output.Tuple<Input<string>?, int>(value, emptySecret).Apply(t => t.Item1);
            }
        }

        /// <summary>
        /// Use 'EXTERNAL' for creating a new database or migrate database key with External HSM.
        /// </summary>
        [Input("providerType")]
        public Input<string>? ProviderType { get; set; }

        public BackupEncryptionKeyLocationDetailGetArgs()
        {
        }
        public static new BackupEncryptionKeyLocationDetailGetArgs Empty => new BackupEncryptionKeyLocationDetailGetArgs();
    }
}
