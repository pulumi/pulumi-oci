// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class JobRunJobConfigurationOverrideDetails
    {
        /// <summary>
        /// The arguments to pass to the job.
        /// </summary>
        public readonly string? CommandLineArguments;
        /// <summary>
        /// Environment variables to set for the job.
        /// </summary>
        public readonly ImmutableDictionary<string, string>? EnvironmentVariables;
        /// <summary>
        /// The type of job.
        /// </summary>
        public readonly string JobType;
        /// <summary>
        /// A time bound for the execution of the job. Timer starts when the job becomes active.
        /// </summary>
        public readonly string? MaximumRuntimeInMinutes;

        [OutputConstructor]
        private JobRunJobConfigurationOverrideDetails(
            string? commandLineArguments,

            ImmutableDictionary<string, string>? environmentVariables,

            string jobType,

            string? maximumRuntimeInMinutes)
        {
            CommandLineArguments = commandLineArguments;
            EnvironmentVariables = environmentVariables;
            JobType = jobType;
            MaximumRuntimeInMinutes = maximumRuntimeInMinutes;
        }
    }
}
