// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Outputs
{

    [OutputType]
    public sealed class MetricExtensionQueryPropertiesScriptDetails
    {
        /// <summary>
        /// (Updatable) Sql statement or script file content as base64 encoded string
        /// </summary>
        public readonly string Content;
        /// <summary>
        /// (Updatable) Name of the script file
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private MetricExtensionQueryPropertiesScriptDetails(
            string content,

            string name)
        {
            Content = content;
            Name = name;
        }
    }
}