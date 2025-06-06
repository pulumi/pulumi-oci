// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration.Inputs
{

    public sealed class WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesArgs : global::Pulumi.ResourceArgs
    {
        [Input("pollCondition")]
        public Input<Inputs.WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesPollConditionArgs>? PollCondition { get; set; }

        [Input("pollInterval")]
        public Input<Inputs.WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesPollIntervalArgs>? PollInterval { get; set; }

        [Input("pollIntervalUnit")]
        public Input<Inputs.WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesPollIntervalUnitArgs>? PollIntervalUnit { get; set; }

        [Input("pollMaxDuration")]
        public Input<Inputs.WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesPollMaxDurationArgs>? PollMaxDuration { get; set; }

        [Input("pollMaxDurationUnit")]
        public Input<Inputs.WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesPollMaxDurationUnitArgs>? PollMaxDurationUnit { get; set; }

        [Input("requestPayload")]
        public Input<Inputs.WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesRequestPayloadArgs>? RequestPayload { get; set; }

        [Input("requestUrl")]
        public Input<Inputs.WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesRequestUrlArgs>? RequestUrl { get; set; }

        public WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesArgs()
        {
        }
        public static new WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesArgs Empty => new WorkspaceTaskPollRestCallConfigConfigValuesConfigParamValuesArgs();
    }
}
