// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class PluggableDatabasesRemoteClonePluggableDatabaseManagementConfigGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The status of the Pluggable Database Management service.
        /// </summary>
        [Input("managementStatus")]
        public Input<string>? ManagementStatus { get; set; }

        public PluggableDatabasesRemoteClonePluggableDatabaseManagementConfigGetArgs()
        {
        }
        public static new PluggableDatabasesRemoteClonePluggableDatabaseManagementConfigGetArgs Empty => new PluggableDatabasesRemoteClonePluggableDatabaseManagementConfigGetArgs();
    }
}
