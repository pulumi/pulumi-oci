// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class TriggerAction
    {
        /// <summary>
        /// (Updatable) The OCID of the build pipeline to be triggered.
        /// </summary>
        public readonly string BuildPipelineId;
        /// <summary>
        /// (Updatable) The filters for the trigger.
        /// </summary>
        public readonly Outputs.TriggerActionFilter? Filter;
        /// <summary>
        /// (Updatable) The type of action that will be taken. Allowed value is TRIGGER_BUILD_PIPELINE.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private TriggerAction(
            string buildPipelineId,

            Outputs.TriggerActionFilter? filter,

            string type)
        {
            BuildPipelineId = buildPipelineId;
            Filter = filter;
            Type = type;
        }
    }
}