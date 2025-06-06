// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class DbSystemMaintenanceWindowDetailsDaysOfWeekArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Name of the day of the week.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public DbSystemMaintenanceWindowDetailsDaysOfWeekArgs()
        {
        }
        public static new DbSystemMaintenanceWindowDetailsDaysOfWeekArgs Empty => new DbSystemMaintenanceWindowDetailsDaysOfWeekArgs();
    }
}
