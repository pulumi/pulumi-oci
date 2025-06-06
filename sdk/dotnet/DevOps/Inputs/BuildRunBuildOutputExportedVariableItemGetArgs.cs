// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class BuildRunBuildOutputExportedVariableItemGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Name of the step.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Value of the argument.
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public BuildRunBuildOutputExportedVariableItemGetArgs()
        {
        }
        public static new BuildRunBuildOutputExportedVariableItemGetArgs Empty => new BuildRunBuildOutputExportedVariableItemGetArgs();
    }
}
