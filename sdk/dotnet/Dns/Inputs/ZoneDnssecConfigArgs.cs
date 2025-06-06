// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns.Inputs
{

    public sealed class ZoneDnssecConfigArgs : global::Pulumi.ResourceArgs
    {
        [Input("kskDnssecKeyVersions")]
        private InputList<Inputs.ZoneDnssecConfigKskDnssecKeyVersionArgs>? _kskDnssecKeyVersions;

        /// <summary>
        /// A read-only array of key signing key (KSK) versions.
        /// </summary>
        public InputList<Inputs.ZoneDnssecConfigKskDnssecKeyVersionArgs> KskDnssecKeyVersions
        {
            get => _kskDnssecKeyVersions ?? (_kskDnssecKeyVersions = new InputList<Inputs.ZoneDnssecConfigKskDnssecKeyVersionArgs>());
            set => _kskDnssecKeyVersions = value;
        }

        [Input("zskDnssecKeyVersions")]
        private InputList<Inputs.ZoneDnssecConfigZskDnssecKeyVersionArgs>? _zskDnssecKeyVersions;

        /// <summary>
        /// A read-only array of zone signing key (ZSK) versions.
        /// </summary>
        public InputList<Inputs.ZoneDnssecConfigZskDnssecKeyVersionArgs> ZskDnssecKeyVersions
        {
            get => _zskDnssecKeyVersions ?? (_zskDnssecKeyVersions = new InputList<Inputs.ZoneDnssecConfigZskDnssecKeyVersionArgs>());
            set => _zskDnssecKeyVersions = value;
        }

        public ZoneDnssecConfigArgs()
        {
        }
        public static new ZoneDnssecConfigArgs Empty => new ZoneDnssecConfigArgs();
    }
}
