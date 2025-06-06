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
    public sealed class MonitoredResourceAliases
    {
        /// <summary>
        /// (Updatable) Monitored Resource Alias Reference Source Credential.
        /// </summary>
        public readonly Outputs.MonitoredResourceAliasesCredential Credential;
        /// <summary>
        /// (Updatable) The name of the alias, within the context of the source.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// (Updatable) The source type and source name combination,delimited with (.) separator. Example: {source type}.{source name} and source type max char limit is 63.
        /// </summary>
        public readonly string Source;

        [OutputConstructor]
        private MonitoredResourceAliases(
            Outputs.MonitoredResourceAliasesCredential credential,

            string name,

            string source)
        {
            Credential = credential;
            Name = name;
            Source = source;
        }
    }
}
