// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class ContainerInstanceContainerSecurityContext
    {
        /// <summary>
        /// Linux Container capabilities to configure capabilities of container.
        /// </summary>
        public readonly Outputs.ContainerInstanceContainerSecurityContextCapabilities? Capabilities;
        /// <summary>
        /// Indicates if the container must run as a non-root user. If true, the service validates the container image at runtime to ensure that it is not going to run with UID 0 (root) and fails the container instance creation if the validation fails.
        /// </summary>
        public readonly bool? IsNonRootUserCheckEnabled;
        /// <summary>
        /// Determines if the container will have a read-only root file system. Default value is false.
        /// </summary>
        public readonly bool? IsRootFileSystemReadonly;
        /// <summary>
        /// The group ID (GID) to run the entrypoint process of the container. Uses runtime default if not provided.
        /// </summary>
        public readonly int? RunAsGroup;
        /// <summary>
        /// The user ID (UID) to run the entrypoint process of the container. Defaults to user specified UID in container image metadata if not provided. This must be provided if runAsGroup is provided.
        /// </summary>
        public readonly int? RunAsUser;
        /// <summary>
        /// The type of security context
        /// </summary>
        public readonly string? SecurityContextType;

        [OutputConstructor]
        private ContainerInstanceContainerSecurityContext(
            Outputs.ContainerInstanceContainerSecurityContextCapabilities? capabilities,

            bool? isNonRootUserCheckEnabled,

            bool? isRootFileSystemReadonly,

            int? runAsGroup,

            int? runAsUser,

            string? securityContextType)
        {
            Capabilities = capabilities;
            IsNonRootUserCheckEnabled = isNonRootUserCheckEnabled;
            IsRootFileSystemReadonly = isRootFileSystemReadonly;
            RunAsGroup = runAsGroup;
            RunAsUser = runAsUser;
            SecurityContextType = securityContextType;
        }
    }
}
