// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class PluggableDatabasesRemoteClonePdbNodeLevelDetailGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The Node name of the Database Instance.
        /// </summary>
        [Input("nodeName")]
        public Input<string>? NodeName { get; set; }

        /// <summary>
        /// The mode that pluggable database is in. Open mode can only be changed to READ_ONLY or MIGRATE directly from the backend (within the Oracle Database software).
        /// </summary>
        [Input("openMode")]
        public Input<string>? OpenMode { get; set; }

        public PluggableDatabasesRemoteClonePdbNodeLevelDetailGetArgs()
        {
        }
        public static new PluggableDatabasesRemoteClonePdbNodeLevelDetailGetArgs Empty => new PluggableDatabasesRemoteClonePdbNodeLevelDetailGetArgs();
    }
}
