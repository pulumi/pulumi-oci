// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Inputs
{

    public sealed class MigrationGoldenGateServiceDetailsSourceContainerDbCredentialsArgs : global::Pulumi.ResourceArgs
    {
        [Input("password", required: true)]
        private Input<string>? _password;

        /// <summary>
        /// (Updatable) Database  password
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
        /// (Updatable) Database username
        /// </summary>
        [Input("username", required: true)]
        public Input<string> Username { get; set; } = null!;

        public MigrationGoldenGateServiceDetailsSourceContainerDbCredentialsArgs()
        {
        }
        public static new MigrationGoldenGateServiceDetailsSourceContainerDbCredentialsArgs Empty => new MigrationGoldenGateServiceDetailsSourceContainerDbCredentialsArgs();
    }
}