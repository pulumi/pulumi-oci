// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi.Outputs
{

    [OutputType]
    public sealed class OpsiConfigurationConfigItem
    {
        /// <summary>
        /// List of contexts in Operations Insights where this configuration item is applicable.
        /// </summary>
        public readonly ImmutableArray<string> ApplicableContexts;
        /// <summary>
        /// (Updatable) Type of configuration item.
        /// </summary>
        public readonly string ConfigItemType;
        /// <summary>
        /// Value of configuration item.
        /// </summary>
        public readonly string? DefaultValue;
        /// <summary>
        /// Configuration item metadata.
        /// </summary>
        public readonly ImmutableArray<Outputs.OpsiConfigurationConfigItemMetadata> Metadatas;
        /// <summary>
        /// (Updatable) Name of configuration item.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// (Updatable) Value of configuration item.
        /// </summary>
        public readonly string? Value;

        [OutputConstructor]
        private OpsiConfigurationConfigItem(
            ImmutableArray<string> applicableContexts,

            string configItemType,

            string? defaultValue,

            ImmutableArray<Outputs.OpsiConfigurationConfigItemMetadata> metadatas,

            string? name,

            string? value)
        {
            ApplicableContexts = applicableContexts;
            ConfigItemType = configItemType;
            DefaultValue = defaultValue;
            Metadatas = metadatas;
            Name = name;
            Value = value;
        }
    }
}
