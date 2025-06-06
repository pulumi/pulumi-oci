// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Inputs
{

    public sealed class ScriptParameterScriptParameterGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// If the parameter value is secret and should be kept confidential, then set isSecret to true.
        /// </summary>
        [Input("isSecret")]
        public Input<bool>? IsSecret { get; set; }

        /// <summary>
        /// Name of the parameter.
        /// </summary>
        [Input("paramName")]
        public Input<string>? ParamName { get; set; }

        /// <summary>
        /// Value of the parameter.
        /// </summary>
        [Input("paramValue")]
        public Input<string>? ParamValue { get; set; }

        public ScriptParameterScriptParameterGetArgs()
        {
        }
        public static new ScriptParameterScriptParameterGetArgs Empty => new ScriptParameterScriptParameterGetArgs();
    }
}
