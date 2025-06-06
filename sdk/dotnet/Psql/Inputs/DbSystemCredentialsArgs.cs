// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Psql.Inputs
{

    public sealed class DbSystemCredentialsArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Details for the database system password. Password can be passed as `VaultSecretPasswordDetails` or `PlainTextPasswordDetails`.
        /// </summary>
        [Input("passwordDetails", required: true)]
        public Input<Inputs.DbSystemCredentialsPasswordDetailsArgs> PasswordDetails { get; set; } = null!;

        /// <summary>
        /// The database system administrator username.
        /// </summary>
        [Input("username", required: true)]
        public Input<string> Username { get; set; } = null!;

        public DbSystemCredentialsArgs()
        {
        }
        public static new DbSystemCredentialsArgs Empty => new DbSystemCredentialsArgs();
    }
}
