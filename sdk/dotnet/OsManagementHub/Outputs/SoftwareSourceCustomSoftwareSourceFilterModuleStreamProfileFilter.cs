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
    public sealed class SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilter
    {
        /// <summary>
        /// (Updatable) The type of the filter.
        /// </summary>
        public readonly string? FilterType;
        /// <summary>
        /// (Updatable) Module name.
        /// </summary>
        public readonly string? ModuleName;
        /// <summary>
        /// (Updatable) Profile name.
        /// </summary>
        public readonly string? ProfileName;
        /// <summary>
        /// (Updatable) Stream name.
        /// </summary>
        public readonly string? StreamName;

        [OutputConstructor]
        private SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilter(
            string? filterType,

            string? moduleName,

            string? profileName,

            string? streamName)
        {
            FilterType = filterType;
            ModuleName = moduleName;
            ProfileName = profileName;
            StreamName = streamName;
        }
    }
}
