// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class AutonomousExadataInfrastructureMaintenanceWindowDetailsDaysOfWeekArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Name of the month of the year.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        public AutonomousExadataInfrastructureMaintenanceWindowDetailsDaysOfWeekArgs()
        {
        }
        public static new AutonomousExadataInfrastructureMaintenanceWindowDetailsDaysOfWeekArgs Empty => new AutonomousExadataInfrastructureMaintenanceWindowDetailsDaysOfWeekArgs();
    }
}