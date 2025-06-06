// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration.Inputs
{

    public sealed class WorkspaceTaskConfigProviderDelegateBindingArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Generated key that can be used in API calls to identify task. On scenarios where reference to the task is needed, a value can be passed in create.
        /// </summary>
        [Input("key")]
        public Input<string>? Key { get; set; }

        [Input("parameterValues")]
        public Input<Inputs.WorkspaceTaskConfigProviderDelegateBindingParameterValuesArgs>? ParameterValues { get; set; }

        public WorkspaceTaskConfigProviderDelegateBindingArgs()
        {
        }
        public static new WorkspaceTaskConfigProviderDelegateBindingArgs Empty => new WorkspaceTaskConfigProviderDelegateBindingArgs();
    }
}
