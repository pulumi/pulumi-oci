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
    public sealed class GetWorkspaceApplicationSourceApplicationInfoResult
    {
        /// <summary>
        /// The application key.
        /// </summary>
        public readonly string ApplicationKey;
        /// <summary>
        /// The source application version of the application.
        /// </summary>
        public readonly string ApplicationVersion;
        public readonly string CopyType;
        /// <summary>
        /// The last patch key for the application.
        /// </summary>
        public readonly string LastPatchKey;
        /// <summary>
        /// The workspace ID.
        /// </summary>
        public readonly string WorkspaceId;

        [OutputConstructor]
        private GetWorkspaceApplicationSourceApplicationInfoResult(
            string applicationKey,

            string applicationVersion,

            string copyType,

            string lastPatchKey,

            string workspaceId)
        {
            ApplicationKey = applicationKey;
            ApplicationVersion = applicationVersion;
            CopyType = copyType;
            LastPatchKey = lastPatchKey;
            WorkspaceId = workspaceId;
        }
    }
}