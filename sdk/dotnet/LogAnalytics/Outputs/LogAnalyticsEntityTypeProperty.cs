// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics.Outputs
{

    [OutputType]
    public sealed class LogAnalyticsEntityTypeProperty
    {
        /// <summary>
        /// Description for the log analytics entity type property.
        /// </summary>
        public readonly string? Description;
        /// <summary>
        /// Log analytics entity type property name. 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private LogAnalyticsEntityTypeProperty(
            string? description,

            string name)
        {
            Description = description;
            Name = name;
        }
    }
}
