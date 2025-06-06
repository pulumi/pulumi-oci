// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class ExadbVmClusterIormConfigCachGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("dbPlans")]
        private InputList<Inputs.ExadbVmClusterIormConfigCachDbPlanGetArgs>? _dbPlans;

        /// <summary>
        /// An array of IORM settings for all the database in the Exadata DB system.
        /// </summary>
        public InputList<Inputs.ExadbVmClusterIormConfigCachDbPlanGetArgs> DbPlans
        {
            get => _dbPlans ?? (_dbPlans = new InputList<Inputs.ExadbVmClusterIormConfigCachDbPlanGetArgs>());
            set => _dbPlans = value;
        }

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The current value for the IORM objective. The default is `AUTO`.
        /// </summary>
        [Input("objective")]
        public Input<string>? Objective { get; set; }

        /// <summary>
        /// The current state of the Exadata VM cluster on Exascale Infrastructure.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public ExadbVmClusterIormConfigCachGetArgs()
        {
        }
        public static new ExadbVmClusterIormConfigCachGetArgs Empty => new ExadbVmClusterIormConfigCachGetArgs();
    }
}
