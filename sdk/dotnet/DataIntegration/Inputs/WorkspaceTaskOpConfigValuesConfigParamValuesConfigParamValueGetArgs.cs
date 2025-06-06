// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration.Inputs
{

    public sealed class WorkspaceTaskOpConfigValuesConfigParamValuesConfigParamValueGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// An integer value of the parameter.
        /// </summary>
        [Input("intValue")]
        public Input<int>? IntValue { get; set; }

        /// <summary>
        /// An object value of the parameter.
        /// </summary>
        [Input("objectValue")]
        public Input<string>? ObjectValue { get; set; }

        /// <summary>
        /// Reference to the parameter by its key.
        /// </summary>
        [Input("parameterValue")]
        public Input<string>? ParameterValue { get; set; }

        /// <summary>
        /// The root object reference value.
        /// </summary>
        [Input("refValue")]
        public Input<Inputs.WorkspaceTaskOpConfigValuesConfigParamValuesConfigParamValueRefValueGetArgs>? RefValue { get; set; }

        /// <summary>
        /// The root object value, used in custom parameters.
        /// </summary>
        [Input("rootObjectValue")]
        public Input<Inputs.WorkspaceTaskOpConfigValuesConfigParamValuesConfigParamValueRootObjectValueGetArgs>? RootObjectValue { get; set; }

        /// <summary>
        /// A string value of the parameter.
        /// </summary>
        [Input("stringValue")]
        public Input<string>? StringValue { get; set; }

        public WorkspaceTaskOpConfigValuesConfigParamValuesConfigParamValueGetArgs()
        {
        }
        public static new WorkspaceTaskOpConfigValuesConfigParamValuesConfigParamValueGetArgs Empty => new WorkspaceTaskOpConfigValuesConfigParamValuesConfigParamValueGetArgs();
    }
}
