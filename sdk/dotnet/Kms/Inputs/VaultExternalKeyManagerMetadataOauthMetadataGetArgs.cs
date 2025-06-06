// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Kms.Inputs
{

    public sealed class VaultExternalKeyManagerMetadataOauthMetadataGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// ID of the client app created in IDP.
        /// </summary>
        [Input("clientAppId", required: true)]
        public Input<string> ClientAppId { get; set; } = null!;

        /// <summary>
        /// Secret of the client app created in IDP.
        /// </summary>
        [Input("clientAppSecret", required: true)]
        public Input<string> ClientAppSecret { get; set; } = null!;

        /// <summary>
        /// Base URL of the IDCS account where confidential client app is created.
        /// </summary>
        [Input("idcsAccountNameUrl", required: true)]
        public Input<string> IdcsAccountNameUrl { get; set; } = null!;

        public VaultExternalKeyManagerMetadataOauthMetadataGetArgs()
        {
        }
        public static new VaultExternalKeyManagerMetadataOauthMetadataGetArgs Empty => new VaultExternalKeyManagerMetadataOauthMetadataGetArgs();
    }
}
