// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration.Outputs
{

    [OutputType]
    public sealed class WorkspaceApplicationSourceApplicationInfo
    {
        /// <summary>
        /// The source application key to use when creating the application.
        /// </summary>
        public readonly string? ApplicationKey;
        /// <summary>
        /// The source application version of the application.
        /// </summary>
        public readonly string? ApplicationVersion;
        /// <summary>
        /// Parameter to specify the link between SOURCE and TARGET application after copying. CONNECTED    - Indicate that TARGET application is conneced to SOURCE and can be synced after copy. DISCONNECTED - Indicate that TARGET application is not conneced to SOURCE and can evolve independently.
        /// </summary>
        public readonly string? CopyType;
        /// <summary>
        /// The last patch key for the application.
        /// </summary>
        public readonly string? LastPatchKey;
        /// <summary>
        /// The workspace ID.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public readonly string? WorkspaceId;

        [OutputConstructor]
        private WorkspaceApplicationSourceApplicationInfo(
            string? applicationKey,

            string? applicationVersion,

            string? copyType,

            string? lastPatchKey,

            string? workspaceId)
        {
            ApplicationKey = applicationKey;
            ApplicationVersion = applicationVersion;
            CopyType = copyType;
            LastPatchKey = lastPatchKey;
            WorkspaceId = workspaceId;
        }
    }
}