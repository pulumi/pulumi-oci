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
    public sealed class WorkspaceTaskOpConfigValuesConfigParamValuesConfigParamValueRootObjectValue
    {
        /// <summary>
        /// (Updatable) Generated key that can be used in API calls to identify task. On scenarios where reference to the task is needed, a value can be passed in create.
        /// </summary>
        public readonly string? Key;
        /// <summary>
        /// (Updatable) The type of the task.
        /// </summary>
        public readonly string? ModelType;
        /// <summary>
        /// (Updatable) The object's model version.
        /// </summary>
        public readonly string? ModelVersion;
        /// <summary>
        /// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
        /// </summary>
        public readonly int? ObjectStatus;

        [OutputConstructor]
        private WorkspaceTaskOpConfigValuesConfigParamValuesConfigParamValueRootObjectValue(
            string? key,

            string? modelType,

            string? modelVersion,

            int? objectStatus)
        {
            Key = key;
            ModelType = modelType;
            ModelVersion = modelVersion;
            ObjectStatus = objectStatus;
        }
    }
}
