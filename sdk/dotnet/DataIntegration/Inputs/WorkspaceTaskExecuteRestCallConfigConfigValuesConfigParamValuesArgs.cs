// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration.Inputs
{

    public sealed class WorkspaceTaskExecuteRestCallConfigConfigValuesConfigParamValuesArgs : global::Pulumi.ResourceArgs
    {
        [Input("requestPayload")]
        public Input<Inputs.WorkspaceTaskExecuteRestCallConfigConfigValuesConfigParamValuesRequestPayloadArgs>? RequestPayload { get; set; }

        [Input("requestUrl")]
        public Input<Inputs.WorkspaceTaskExecuteRestCallConfigConfigValuesConfigParamValuesRequestUrlArgs>? RequestUrl { get; set; }

        public WorkspaceTaskExecuteRestCallConfigConfigValuesConfigParamValuesArgs()
        {
        }
        public static new WorkspaceTaskExecuteRestCallConfigConfigValuesConfigParamValuesArgs Empty => new WorkspaceTaskExecuteRestCallConfigConfigValuesConfigParamValuesArgs();
    }
}
