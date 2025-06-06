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
    public sealed class GetWorkspaceTaskMetadataAggregatorResult
    {
        /// <summary>
        /// Detailed description for the object.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
        /// </summary>
        public readonly string Identifier;
        /// <summary>
        /// The key of the object.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The object type.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetWorkspaceTaskMetadataAggregatorResult(
            string description,

            string identifier,

            string key,

            string name,

            string type)
        {
            Description = description;
            Identifier = identifier;
            Key = key;
            Name = name;
            Type = type;
        }
    }
}
