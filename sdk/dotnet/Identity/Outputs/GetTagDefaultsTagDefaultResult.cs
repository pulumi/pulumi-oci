// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetTagDefaultsTagDefaultResult
    {
        /// <summary>
        /// The OCID of the compartment (remember that the tenancy is simply the root compartment).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A filter to only return resources that match the specified OCID exactly.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// If you specify that a value is required, a value is set during resource creation (either by the user creating the resource or another tag defualt). If no value is set, resource creation is blocked.
        /// * If the `isRequired` flag is set to "true", the value is set during resource creation.
        /// * If the `isRequired` flag is set to "false", the value you enter is set during resource creation.
        /// </summary>
        public readonly bool IsRequired;
        /// <summary>
        /// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The OCID of the tag definition.
        /// </summary>
        public readonly string TagDefinitionId;
        /// <summary>
        /// The name used in the tag definition. This field is informational in the context of the tag default.
        /// </summary>
        public readonly string TagDefinitionName;
        /// <summary>
        /// The OCID of the tag namespace that contains the tag definition.
        /// </summary>
        public readonly string TagNamespaceId;
        /// <summary>
        /// Date and time the `TagDefault` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The default value for the tag definition. This will be applied to all new resources created in the compartment.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetTagDefaultsTagDefaultResult(
            string compartmentId,

            string id,

            bool isRequired,

            string state,

            string tagDefinitionId,

            string tagDefinitionName,

            string tagNamespaceId,

            string timeCreated,

            string value)
        {
            CompartmentId = compartmentId;
            Id = id;
            IsRequired = isRequired;
            State = state;
            TagDefinitionId = tagDefinitionId;
            TagDefinitionName = tagDefinitionName;
            TagNamespaceId = tagNamespaceId;
            TimeCreated = timeCreated;
            Value = value;
        }
    }
}
