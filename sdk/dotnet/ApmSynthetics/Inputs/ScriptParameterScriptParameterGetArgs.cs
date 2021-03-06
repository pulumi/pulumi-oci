// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Inputs
{

    public sealed class ScriptParameterScriptParameterGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) If the parameter value is secret and should be kept confidential, then set isSecret to true.
        /// </summary>
        [Input("isSecret")]
        public Input<bool>? IsSecret { get; set; }

        /// <summary>
        /// (Updatable) Name of the parameter.
        /// </summary>
        [Input("paramName")]
        public Input<string>? ParamName { get; set; }

        /// <summary>
        /// (Updatable) Value of the parameter.
        /// </summary>
        [Input("paramValue")]
        public Input<string>? ParamValue { get; set; }

        public ScriptParameterScriptParameterGetArgs()
        {
        }
    }
}
