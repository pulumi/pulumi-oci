// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Inputs
{

    public sealed class ModelDeploymentCategoryLogDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The log details.
        /// </summary>
        [Input("access")]
        public Input<Inputs.ModelDeploymentCategoryLogDetailsAccessGetArgs>? Access { get; set; }

        /// <summary>
        /// (Updatable) The log details.
        /// </summary>
        [Input("predict")]
        public Input<Inputs.ModelDeploymentCategoryLogDetailsPredictGetArgs>? Predict { get; set; }

        public ModelDeploymentCategoryLogDetailsGetArgs()
        {
        }
        public static new ModelDeploymentCategoryLogDetailsGetArgs Empty => new ModelDeploymentCategoryLogDetailsGetArgs();
    }
}
