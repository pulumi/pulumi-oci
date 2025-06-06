// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Outputs
{

    [OutputType]
    public sealed class ConfigScriptParameter
    {
        /// <summary>
        /// If parameter value is default or overwritten.
        /// </summary>
        public readonly bool? IsOverwritten;
        /// <summary>
        /// Describes if  the parameter value is secret and should be kept confidential. isSecret is specified in either CreateScript or UpdateScript API.
        /// </summary>
        public readonly bool? IsSecret;
        /// <summary>
        /// Details of the script parameter that can be used to overwrite the parameter present in the script.
        /// </summary>
        public readonly ImmutableArray<Outputs.ConfigScriptParameterMonitorScriptParameter> MonitorScriptParameters;
        /// <summary>
        /// (Updatable) Name of the parameter.
        /// </summary>
        public readonly string ParamName;
        /// <summary>
        /// (Updatable) Value of the parameter.
        /// </summary>
        public readonly string ParamValue;

        [OutputConstructor]
        private ConfigScriptParameter(
            bool? isOverwritten,

            bool? isSecret,

            ImmutableArray<Outputs.ConfigScriptParameterMonitorScriptParameter> monitorScriptParameters,

            string paramName,

            string paramValue)
        {
            IsOverwritten = isOverwritten;
            IsSecret = isSecret;
            MonitorScriptParameters = monitorScriptParameters;
            ParamName = paramName;
            ParamValue = paramValue;
        }
    }
}
