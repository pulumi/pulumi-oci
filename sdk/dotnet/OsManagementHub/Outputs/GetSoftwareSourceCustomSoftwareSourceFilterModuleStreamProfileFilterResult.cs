// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub.Outputs
{

    [OutputType]
    public sealed class GetSoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilterResult
    {
        /// <summary>
        /// The type of the filter.
        /// </summary>
        public readonly string FilterType;
        /// <summary>
        /// Module name.
        /// </summary>
        public readonly string ModuleName;
        /// <summary>
        /// Profile name.
        /// </summary>
        public readonly string ProfileName;
        /// <summary>
        /// Stream name.
        /// </summary>
        public readonly string StreamName;

        [OutputConstructor]
        private GetSoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilterResult(
            string filterType,

            string moduleName,

            string profileName,

            string streamName)
        {
            FilterType = filterType;
            ModuleName = moduleName;
            ProfileName = profileName;
            StreamName = streamName;
        }
    }
}
