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
    public sealed class GetBuildPipelinesBuildPipelineCollectionItemBuildPipelineParameterItemResult
    {
        /// <summary>
        /// Default value of the parameter.
        /// </summary>
        public readonly string DefaultValue;
        /// <summary>
        /// Optional description about the build pipeline.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Name of the parameter (case-sensitive). Parameter name must be ^[a-zA-Z][a-zA-Z_0-9]*$. Example: 'Build_Pipeline_param' is not same as 'build_pipeline_Param'
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetBuildPipelinesBuildPipelineCollectionItemBuildPipelineParameterItemResult(
            string defaultValue,

            string description,

            string name)
        {
            DefaultValue = defaultValue;
            Description = description;
            Name = name;
        }
    }
}