// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate.Inputs
{

    public sealed class DeploymentMaintenanceWindowArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Days of the week.
        /// </summary>
        [Input("day", required: true)]
        public Input<string> Day { get; set; } = null!;

        /// <summary>
        /// (Updatable) Start hour for maintenance period. Hour is in UTC.
        /// </summary>
        [Input("startHour", required: true)]
        public Input<int> StartHour { get; set; } = null!;

        public DeploymentMaintenanceWindowArgs()
        {
        }
        public static new DeploymentMaintenanceWindowArgs Empty => new DeploymentMaintenanceWindowArgs();
    }
}
