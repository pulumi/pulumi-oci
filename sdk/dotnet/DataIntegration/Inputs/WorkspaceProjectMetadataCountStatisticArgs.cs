// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration.Inputs
{

    public sealed class WorkspaceProjectMetadataCountStatisticArgs : global::Pulumi.ResourceArgs
    {
        [Input("objectTypeCountLists")]
        private InputList<Inputs.WorkspaceProjectMetadataCountStatisticObjectTypeCountListArgs>? _objectTypeCountLists;

        /// <summary>
        /// The array of statistics.
        /// </summary>
        public InputList<Inputs.WorkspaceProjectMetadataCountStatisticObjectTypeCountListArgs> ObjectTypeCountLists
        {
            get => _objectTypeCountLists ?? (_objectTypeCountLists = new InputList<Inputs.WorkspaceProjectMetadataCountStatisticObjectTypeCountListArgs>());
            set => _objectTypeCountLists = value;
        }

        public WorkspaceProjectMetadataCountStatisticArgs()
        {
        }
        public static new WorkspaceProjectMetadataCountStatisticArgs Empty => new WorkspaceProjectMetadataCountStatisticArgs();
    }
}
