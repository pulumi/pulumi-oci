// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class AdhocQueryAdhocQueryDetailsAdhocQueryResourceGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Region in which adhoc query needs to be run
        /// </summary>
        [Input("region")]
        public Input<string>? Region { get; set; }

        [Input("resourceIds")]
        private InputList<string>? _resourceIds;

        /// <summary>
        /// List of OCIDs on which query needs to be run
        /// </summary>
        public InputList<string> ResourceIds
        {
            get => _resourceIds ?? (_resourceIds = new InputList<string>());
            set => _resourceIds = value;
        }

        /// <summary>
        /// Type of resource
        /// </summary>
        [Input("resourceType")]
        public Input<string>? ResourceType { get; set; }

        public AdhocQueryAdhocQueryDetailsAdhocQueryResourceGetArgs()
        {
        }
        public static new AdhocQueryAdhocQueryDetailsAdhocQueryResourceGetArgs Empty => new AdhocQueryAdhocQueryDetailsAdhocQueryResourceGetArgs();
    }
}
