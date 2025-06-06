// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class PluggableDatabaseRefreshableCloneConfigArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Indicates whether the Pluggable Database is a refreshable clone.
        /// </summary>
        [Input("isRefreshableClone")]
        public Input<bool>? IsRefreshableClone { get; set; }

        public PluggableDatabaseRefreshableCloneConfigArgs()
        {
        }
        public static new PluggableDatabaseRefreshableCloneConfigArgs Empty => new PluggableDatabaseRefreshableCloneConfigArgs();
    }
}
