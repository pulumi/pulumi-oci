// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class ExadataInfrastructureComputeMaintenanceWindowDaysOfWeekGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Name of the month of the year.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public ExadataInfrastructureComputeMaintenanceWindowDaysOfWeekGetArgs()
        {
        }
        public static new ExadataInfrastructureComputeMaintenanceWindowDaysOfWeekGetArgs Empty => new ExadataInfrastructureComputeMaintenanceWindowDaysOfWeekGetArgs();
    }
}
