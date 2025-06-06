// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FileStorage.Inputs
{

    public sealed class ExportExportOptionGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Type of access to grant clients using the file system through this export. If unspecified defaults to `READ_WRITE`.
        /// </summary>
        [Input("access")]
        public Input<string>? Access { get; set; }

        [Input("allowedAuths")]
        private InputList<string>? _allowedAuths;

        /// <summary>
        /// (Updatable) Array of allowed NFS authentication types.
        /// </summary>
        public InputList<string> AllowedAuths
        {
            get => _allowedAuths ?? (_allowedAuths = new InputList<string>());
            set => _allowedAuths = value;
        }

        /// <summary>
        /// (Updatable) GID value to remap to when squashing a client GID (see identitySquash for more details.) If unspecified defaults to `65534`.
        /// </summary>
        [Input("anonymousGid")]
        public Input<string>? AnonymousGid { get; set; }

        /// <summary>
        /// (Updatable) UID value to remap to when squashing a client UID (see identitySquash for more details.) If unspecified, defaults to `65534`.
        /// </summary>
        [Input("anonymousUid")]
        public Input<string>? AnonymousUid { get; set; }

        /// <summary>
        /// (Updatable) Used when clients accessing the file system through this export have their UID and GID remapped to 'anonymousUid' and 'anonymousGid'. If `ALL`, all users and groups are remapped; if `ROOT`, only the root user and group (UID/GID 0) are remapped; if `NONE`, no remapping is done. If unspecified, defaults to `ROOT`.
        /// </summary>
        [Input("identitySquash")]
        public Input<string>? IdentitySquash { get; set; }

        /// <summary>
        /// (Updatable) Whether or not to enable anonymous access to the file system through this export in cases where a user isn't found in the LDAP server used for ID mapping. If true, and the user is not found in the LDAP directory, the operation uses the Squash UID and Squash GID.
        /// </summary>
        [Input("isAnonymousAccessAllowed")]
        public Input<bool>? IsAnonymousAccessAllowed { get; set; }

        /// <summary>
        /// (Updatable) If `true`, clients accessing the file system through this export must connect from a privileged source port. If unspecified, defaults to `true`.
        /// </summary>
        [Input("requirePrivilegedSourcePort")]
        public Input<bool>? RequirePrivilegedSourcePort { get; set; }

        /// <summary>
        /// (Updatable) Clients these options should apply to. Must be a either single IPv4 address or single IPv4 CIDR block.
        /// 
        /// **Note:** Access will also be limited by any applicable VCN security rules and the ability to route IP packets to the mount target. Mount targets do not have Internet-routable IP addresses.
        /// </summary>
        [Input("source", required: true)]
        public Input<string> Source { get; set; } = null!;

        public ExportExportOptionGetArgs()
        {
        }
        public static new ExportExportOptionGetArgs Empty => new ExportExportOptionGetArgs();
    }
}
