// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration.Inputs
{

    public sealed class WorkspaceTaskTypedExpressionConfigValuesConfigParamValuesScaleGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// An integer value of the parameter.
        /// </summary>
        [Input("intValue")]
        public Input<int>? IntValue { get; set; }

        public WorkspaceTaskTypedExpressionConfigValuesConfigParamValuesScaleGetArgs()
        {
        }
        public static new WorkspaceTaskTypedExpressionConfigValuesConfigParamValuesScaleGetArgs Empty => new WorkspaceTaskTypedExpressionConfigValuesConfigParamValuesScaleGetArgs();
    }
}
