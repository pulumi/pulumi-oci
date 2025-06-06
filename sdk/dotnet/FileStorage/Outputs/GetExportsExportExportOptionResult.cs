// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FileStorage.Outputs
{

    [OutputType]
    public sealed class GetExportsExportExportOptionResult
    {
        /// <summary>
        /// Type of access to grant clients using the file system through this export. If unspecified defaults to `READ_WRITE`.
        /// </summary>
        public readonly string Access;
        /// <summary>
        /// Array of allowed NFS authentication types.
        /// </summary>
        public readonly ImmutableArray<string> AllowedAuths;
        /// <summary>
        /// GID value to remap to when squashing a client GID (see identitySquash for more details.) If unspecified defaults to `65534`.
        /// </summary>
        public readonly string AnonymousGid;
        /// <summary>
        /// UID value to remap to when squashing a client UID (see identitySquash for more details.) If unspecified, defaults to `65534`.
        /// </summary>
        public readonly string AnonymousUid;
        /// <summary>
        /// Used when clients accessing the file system through this export have their UID and GID remapped to 'anonymousUid' and 'anonymousGid'. If `ALL`, all users and groups are remapped; if `ROOT`, only the root user and group (UID/GID 0) are remapped; if `NONE`, no remapping is done. If unspecified, defaults to `ROOT`.
        /// </summary>
        public readonly string IdentitySquash;
        /// <summary>
        /// Whether or not to enable anonymous access to the file system through this export in cases where a user isn't found in the LDAP server used for ID mapping. If true, and the user is not found in the LDAP directory, the operation uses the Squash UID and Squash GID.
        /// </summary>
        public readonly bool IsAnonymousAccessAllowed;
        /// <summary>
        /// If `true`, clients accessing the file system through this export must connect from a privileged source port. If unspecified, defaults to `true`.
        /// </summary>
        public readonly bool RequirePrivilegedSourcePort;
        /// <summary>
        /// Clients these options should apply to. Must be a either single IPv4 address or single IPv4 CIDR block.
        /// </summary>
        public readonly string Source;

        [OutputConstructor]
        private GetExportsExportExportOptionResult(
            string access,

            ImmutableArray<string> allowedAuths,

            string anonymousGid,

            string anonymousUid,

            string identitySquash,

            bool isAnonymousAccessAllowed,

            bool requirePrivilegedSourcePort,

            string source)
        {
            Access = access;
            AllowedAuths = allowedAuths;
            AnonymousGid = anonymousGid;
            AnonymousUid = anonymousUid;
            IdentitySquash = identitySquash;
            IsAnonymousAccessAllowed = isAnonymousAccessAllowed;
            RequirePrivilegedSourcePort = requirePrivilegedSourcePort;
            Source = source;
        }
    }
}
