// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration.Inputs
{

    public sealed class WorkspaceTaskParameterConfigValuesConfigParamValuesConfigParamValueRefValueGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Generated key that can be used in API calls to identify task. On scenarios where reference to the task is needed, a value can be passed in create.
        /// </summary>
        [Input("key")]
        public Input<string>? Key { get; set; }

        /// <summary>
        /// (Updatable) The type of the task.
        /// </summary>
        [Input("modelType")]
        public Input<string>? ModelType { get; set; }

        /// <summary>
        /// (Updatable) The object's model version.
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

        public WorkspaceTaskParameterConfigValuesConfigParamValuesConfigParamValueRefValueGetArgs()
        {
        }
        public static new WorkspaceTaskParameterConfigValuesConfigParamValuesConfigParamValueRefValueGetArgs Empty => new WorkspaceTaskParameterConfigValuesConfigParamValuesConfigParamValueRefValueGetArgs();
    }
}
