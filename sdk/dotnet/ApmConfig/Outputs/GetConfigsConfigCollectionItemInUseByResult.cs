// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmConfig.Outputs
{

    [OutputType]
    public sealed class GetConfigsConfigCollectionItemInUseByResult
    {
        /// <summary>
        /// A filter to match configuration items of a given type. Supported values are SPAN_FILTER, METRIC_GROUP, and APDEX.
        /// </summary>
        public readonly string ConfigType;
        /// <summary>
        /// A filter to return resources that match the given display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the configuration item. An OCID is generated when the item is created.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A filter to return OPTIONS resources that match the given group.
        /// </summary>
        public readonly string OptionsGroup;

        [OutputConstructor]
        private GetConfigsConfigCollectionItemInUseByResult(
            string configType,

            string displayName,

            string id,

            string optionsGroup)
        {
            ConfigType = configType;
            DisplayName = displayName;
            Id = id;
            OptionsGroup = optionsGroup;
        }
    }
}