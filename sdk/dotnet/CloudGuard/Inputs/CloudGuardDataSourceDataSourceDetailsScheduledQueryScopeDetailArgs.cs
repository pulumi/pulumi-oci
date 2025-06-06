// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class CloudGuardDataSourceDataSourceDetailsScheduledQueryScopeDetailArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) region on which scheduled query needs to be run
        /// </summary>
        [Input("region")]
        public Input<string>? Region { get; set; }

        [Input("resourceIds")]
        private InputList<string>? _resourceIds;

        /// <summary>
        /// (Updatable) List of OCIDs on scheduled query needs to run
        /// </summary>
        public InputList<string> ResourceIds
        {
            get => _resourceIds ?? (_resourceIds = new InputList<string>());
            set => _resourceIds = value;
        }

        /// <summary>
        /// (Updatable) Type of resource
        /// </summary>
        [Input("resourceType")]
        public Input<string>? ResourceType { get; set; }

        public CloudGuardDataSourceDataSourceDetailsScheduledQueryScopeDetailArgs()
        {
        }
        public static new CloudGuardDataSourceDataSourceDetailsScheduledQueryScopeDetailArgs Empty => new CloudGuardDataSourceDataSourceDetailsScheduledQueryScopeDetailArgs();
    }
}
