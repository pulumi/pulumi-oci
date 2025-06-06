// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Outputs
{

    [OutputType]
    public sealed class MetricExtensionQueryPropertiesSqlDetails
    {
        /// <summary>
        /// (Updatable) Sql statement or script file content as base64 encoded string
        /// </summary>
        public readonly string Content;
        /// <summary>
        /// (Updatable) If a script needs to be executed, then provide file name of the script
        /// </summary>
        public readonly string? ScriptFileName;

        [OutputConstructor]
        private MetricExtensionQueryPropertiesSqlDetails(
            string content,

            string? scriptFileName)
        {
            Content = content;
            ScriptFileName = scriptFileName;
        }
    }
}
