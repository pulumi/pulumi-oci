// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class TriggerActionGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the build pipeline to be triggered.
        /// </summary>
        [Input("buildPipelineId", required: true)]
        public Input<string> BuildPipelineId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The filters for the trigger.
        /// </summary>
        [Input("filter")]
        public Input<Inputs.TriggerActionFilterGetArgs>? Filter { get; set; }

        /// <summary>
        /// (Updatable) The type of action that will be taken. Allowed value is TRIGGER_BUILD_PIPELINE.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public TriggerActionGetArgs()
        {
        }
        public static new TriggerActionGetArgs Empty => new TriggerActionGetArgs();
    }
}