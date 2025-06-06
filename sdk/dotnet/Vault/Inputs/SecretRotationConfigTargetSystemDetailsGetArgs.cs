// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Vault.Inputs
{

    public sealed class SecretRotationConfigTargetSystemDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The unique identifier (OCID) for the autonomous database that Vault Secret connects to.
        /// </summary>
        [Input("adbId")]
        public Input<string>? AdbId { get; set; }

        /// <summary>
        /// (Updatable) The unique identifier (OCID) of the Oracle Cloud Infrastructure Functions that vault secret connects to.
        /// </summary>
        [Input("functionId")]
        public Input<string>? FunctionId { get; set; }

        /// <summary>
        /// (Updatable) Unique identifier of the target system that Vault Secret connects to.
        /// </summary>
        [Input("targetSystemType", required: true)]
        public Input<string> TargetSystemType { get; set; } = null!;

        public SecretRotationConfigTargetSystemDetailsGetArgs()
        {
        }
        public static new SecretRotationConfigTargetSystemDetailsGetArgs Empty => new SecretRotationConfigTargetSystemDetailsGetArgs();
    }
}
