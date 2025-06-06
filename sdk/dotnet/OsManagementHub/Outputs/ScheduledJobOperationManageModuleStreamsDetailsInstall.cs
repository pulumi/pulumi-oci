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
    public sealed class ScheduledJobOperationManageModuleStreamsDetailsInstall
    {
        /// <summary>
        /// (Updatable) The name of a module.
        /// </summary>
        public readonly string ModuleName;
        /// <summary>
        /// (Updatable) The name of a profile of the specified module stream.
        /// </summary>
        public readonly string ProfileName;
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source that contains the module stream.
        /// </summary>
        public readonly string? SoftwareSourceId;
        /// <summary>
        /// (Updatable) The name of a stream of the specified module.
        /// </summary>
        public readonly string StreamName;

        [OutputConstructor]
        private ScheduledJobOperationManageModuleStreamsDetailsInstall(
            string moduleName,

            string profileName,

            string? softwareSourceId,

            string streamName)
        {
            ModuleName = moduleName;
            ProfileName = profileName;
            SoftwareSourceId = softwareSourceId;
            StreamName = streamName;
        }
    }
}
