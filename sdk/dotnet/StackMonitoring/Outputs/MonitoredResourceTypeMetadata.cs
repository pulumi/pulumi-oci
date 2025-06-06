// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Outputs
{

    [OutputType]
    public sealed class MonitoredResourceTypeMetadata
    {
        /// <summary>
        /// (Updatable) List of properties needed by the agent for monitoring the resource.  Valid only if resource type is Oracle Cloud Infrastructure management agent based. When specified,  these properties are passed to the management agent during resource create or update.
        /// </summary>
        public readonly ImmutableArray<string> AgentProperties;
        /// <summary>
        /// (Updatable) ResourceType metadata format to be used. Currently supports only one format. Possible values - SYSTEM_FORMAT.
        /// * SYSTEM_FORMAT - The resource type metadata is defined in machine friendly format.
        /// </summary>
        public readonly string Format;
        /// <summary>
        /// (Updatable) List of required properties for resource type.
        /// </summary>
        public readonly ImmutableArray<string> RequiredProperties;
        /// <summary>
        /// (Updatable) List of property sets used to uniquely identify the resources.  This check is made during create or update of stack monitoring resource.  The resource has to pass unique check for each set in the list.  For example, database can have user, password and SID as one unique set.  Another unique set would be user, password and service name.
        /// </summary>
        public readonly ImmutableArray<Outputs.MonitoredResourceTypeMetadataUniquePropertySet> UniquePropertySets;
        /// <summary>
        /// (Updatable) List of valid properties for resource type while creating the monitored resource.  If resources of this type specifies any other properties during create operation,  the operation will fail.
        /// </summary>
        public readonly ImmutableArray<string> ValidPropertiesForCreates;
        /// <summary>
        /// (Updatable) List of valid properties for resource type while updating the monitored resource.  If resources of this type specifies any other properties during update operation,  the operation will fail.
        /// </summary>
        public readonly ImmutableArray<string> ValidPropertiesForUpdates;
        /// <summary>
        /// (Updatable) List of valid values for the properties. This is useful when resource type wants to restrict only certain values for some properties. For instance for 'osType' property,  supported values can be restricted to be either Linux or Windows. Example: `{ "osType": "Linux,Windows,Solaris"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string>? ValidPropertyValues;
        /// <summary>
        /// (Updatable) List of valid sub-resource types for a composite resource type. The sub-resource types will be obtained from the valid association pairs corresponding to the composite resource types. It will be empty for non composite resource types
        /// </summary>
        public readonly ImmutableArray<string> ValidSubResourceTypes;

        [OutputConstructor]
        private MonitoredResourceTypeMetadata(
            ImmutableArray<string> agentProperties,

            string format,

            ImmutableArray<string> requiredProperties,

            ImmutableArray<Outputs.MonitoredResourceTypeMetadataUniquePropertySet> uniquePropertySets,

            ImmutableArray<string> validPropertiesForCreates,

            ImmutableArray<string> validPropertiesForUpdates,

            ImmutableDictionary<string, string>? validPropertyValues,

            ImmutableArray<string> validSubResourceTypes)
        {
            AgentProperties = agentProperties;
            Format = format;
            RequiredProperties = requiredProperties;
            UniquePropertySets = uniquePropertySets;
            ValidPropertiesForCreates = validPropertiesForCreates;
            ValidPropertiesForUpdates = validPropertiesForUpdates;
            ValidPropertyValues = validPropertyValues;
            ValidSubResourceTypes = validSubResourceTypes;
        }
    }
}
