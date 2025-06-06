// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub.Inputs
{

    public sealed class ManagedInstanceGroupManageModuleStreamsManagementInstallArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The name of a module.
        /// </summary>
        [Input("moduleName", required: true)]
        public Input<string> ModuleName { get; set; } = null!;

        /// <summary>
        /// The name of a profile of the specified module stream.
        /// </summary>
        [Input("profileName", required: true)]
        public Input<string> ProfileName { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source that contains the module stream.
        /// </summary>
        [Input("softwareSourceId")]
        public Input<string>? SoftwareSourceId { get; set; }

        /// <summary>
        /// The name of a stream of the specified module.
        /// </summary>
        [Input("streamName", required: true)]
        public Input<string> StreamName { get; set; } = null!;

        public ManagedInstanceGroupManageModuleStreamsManagementInstallArgs()
        {
        }
        public static new ManagedInstanceGroupManageModuleStreamsManagementInstallArgs Empty => new ManagedInstanceGroupManageModuleStreamsManagementInstallArgs();
    }
}
