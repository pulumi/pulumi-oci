// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration.Inputs
{

    public sealed class WorkspaceTaskTypedExpressionArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Configuration values can be string, objects, or parameters.
        /// </summary>
        [Input("configValues")]
        public Input<Inputs.WorkspaceTaskTypedExpressionConfigValuesArgs>? ConfigValues { get; set; }

        /// <summary>
        /// (Updatable) Detailed description for the object.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The expression string for the object.
        /// </summary>
        [Input("expression")]
        public Input<string>? Expression { get; set; }

        /// <summary>
        /// (Updatable) The key of the object.
        /// </summary>
        [Input("key")]
        public Input<string>? Key { get; set; }

        /// <summary>
        /// (Updatable) The type of the types object.
        /// </summary>
        [Input("modelType")]
        public Input<string>? ModelType { get; set; }

        /// <summary>
        /// (Updatable) The model version of an object.
        /// </summary>
        [Input("modelVersion")]
        public Input<string>? ModelVersion { get; set; }

        /// <summary>
        /// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
        /// </summary>
        [Input("objectStatus")]
        public Input<int>? ObjectStatus { get; set; }

        /// <summary>
        /// (Updatable) A reference to the object's parent.
        /// </summary>
        [Input("parentRef")]
        public Input<Inputs.WorkspaceTaskTypedExpressionParentRefArgs>? ParentRef { get; set; }

        /// <summary>
        /// (Updatable) The object type.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public WorkspaceTaskTypedExpressionArgs()
        {
        }
        public static new WorkspaceTaskTypedExpressionArgs Empty => new WorkspaceTaskTypedExpressionArgs();
    }
}
