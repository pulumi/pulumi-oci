// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Inputs
{

    public sealed class FleetCredentialEntitySpecificsVariableArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Name of the variable.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) The value corresponding to the variable name.
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public FleetCredentialEntitySpecificsVariableArgs()
        {
        }
        public static new FleetCredentialEntitySpecificsVariableArgs Empty => new FleetCredentialEntitySpecificsVariableArgs();
    }
}
