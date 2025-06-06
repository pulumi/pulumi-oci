// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging.Outputs
{

    [OutputType]
    public sealed class LogConfiguration
    {
        /// <summary>
        /// The OCID of the compartment that the resource belongs to.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// The source the log object comes from.
        /// </summary>
        public readonly Outputs.LogConfigurationSource Source;

        [OutputConstructor]
        private LogConfiguration(
            string? compartmentId,

            Outputs.LogConfigurationSource source)
        {
            CompartmentId = compartmentId;
            Source = source;
        }
    }
}
