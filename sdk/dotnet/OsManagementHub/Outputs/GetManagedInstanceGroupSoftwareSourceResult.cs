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
    public sealed class GetManagedInstanceGroupSoftwareSourceResult
    {
        /// <summary>
        /// Software source description.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Software source name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates whether this is a required software source for Autonomous Linux instances. If true, the user can't unselect it.
        /// </summary>
        public readonly bool IsMandatoryForAutonomousLinux;
        /// <summary>
        /// Type of the software source.
        /// </summary>
        public readonly string SoftwareSourceType;

        [OutputConstructor]
        private GetManagedInstanceGroupSoftwareSourceResult(
            string description,

            string displayName,

            string id,

            bool isMandatoryForAutonomousLinux,

            string softwareSourceType)
        {
            Description = description;
            DisplayName = displayName;
            Id = id;
            IsMandatoryForAutonomousLinux = isMandatoryForAutonomousLinux;
            SoftwareSourceType = softwareSourceType;
        }
    }
}
