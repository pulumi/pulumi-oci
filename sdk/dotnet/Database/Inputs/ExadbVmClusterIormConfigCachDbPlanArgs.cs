// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class ExadbVmClusterIormConfigCachDbPlanArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The database name. For the default `DbPlan`, the `dbName` is `default`.
        /// </summary>
        [Input("dbName")]
        public Input<string>? DbName { get; set; }

        /// <summary>
        /// The flash cache limit for this database. This value is internally configured based on the share value assigned to the database.
        /// </summary>
        [Input("flashCacheLimit")]
        public Input<string>? FlashCacheLimit { get; set; }

        /// <summary>
        /// The relative priority of this database.
        /// </summary>
        [Input("share")]
        public Input<int>? Share { get; set; }

        public ExadbVmClusterIormConfigCachDbPlanArgs()
        {
        }
        public static new ExadbVmClusterIormConfigCachDbPlanArgs Empty => new ExadbVmClusterIormConfigCachDbPlanArgs();
    }
}
