// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class MaintenanceRunEstimatedPatchingTimeArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The estimated time required in minutes for database server patching.
        /// </summary>
        [Input("estimatedDbServerPatchingTime")]
        public Input<int>? EstimatedDbServerPatchingTime { get; set; }

        /// <summary>
        /// The estimated time required in minutes for network switch patching.
        /// </summary>
        [Input("estimatedNetworkSwitchesPatchingTime")]
        public Input<int>? EstimatedNetworkSwitchesPatchingTime { get; set; }

        /// <summary>
        /// The estimated time required in minutes for storage server patching.
        /// </summary>
        [Input("estimatedStorageServerPatchingTime")]
        public Input<int>? EstimatedStorageServerPatchingTime { get; set; }

        /// <summary>
        /// The estimated total time required in minutes for all patching operations.
        /// </summary>
        [Input("totalEstimatedPatchingTime")]
        public Input<int>? TotalEstimatedPatchingTime { get; set; }

        public MaintenanceRunEstimatedPatchingTimeArgs()
        {
        }
        public static new MaintenanceRunEstimatedPatchingTimeArgs Empty => new MaintenanceRunEstimatedPatchingTimeArgs();
    }
}
