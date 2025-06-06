// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration.Outputs
{

    [OutputType]
    public sealed class GetWorkspaceTasksTaskSummaryCollectionItemParameterConfigValuesConfigParamValuesConfigParamValueRefValueResult
    {
        /// <summary>
        /// Used to filter by the key of the object.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// The type of the types object.
        /// </summary>
        public readonly string ModelType;
        /// <summary>
        /// The model version of an object.
        /// </summary>
        public readonly string ModelVersion;
        /// <summary>
        /// Used to filter by the name of the object.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
        /// </summary>
        public readonly int ObjectStatus;

        [OutputConstructor]
        private GetWorkspaceTasksTaskSummaryCollectionItemParameterConfigValuesConfigParamValuesConfigParamValueRefValueResult(
            string key,

            string modelType,

            string modelVersion,

            string name,

            int objectStatus)
        {
            Key = key;
            ModelType = modelType;
            ModelVersion = modelVersion;
            Name = name;
            ObjectStatus = objectStatus;
        }
    }
}
