// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataConnectivity.Inputs
{

    public sealed class RegistryConnectionPrimarySchemaArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The default connection key.
        /// </summary>
        [Input("defaultConnection")]
        public Input<string>? DefaultConnection { get; set; }

        /// <summary>
        /// (Updatable) The description of the aggregator.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The external key for the object.
        /// </summary>
        [Input("externalKey")]
        public Input<string>? ExternalKey { get; set; }

        /// <summary>
        /// (Updatable) The identifier of the aggregator.
        /// </summary>
        [Input("identifier", required: true)]
        public Input<string> Identifier { get; set; } = null!;

        /// <summary>
        /// (Updatable) Specifies whether the schema has containers.
        /// </summary>
        [Input("isHasContainers")]
        public Input<bool>? IsHasContainers { get; set; }

        /// <summary>
        /// (Updatable) The identifying key for the object.
        /// </summary>
        [Input("key", required: true)]
        public Input<string> Key { get; set; } = null!;

        /// <summary>
        /// (Updatable) A summary type containing information about the object including its key, name and when/who created/updated it.
        /// </summary>
        [Input("metadata")]
        public Input<Inputs.RegistryConnectionPrimarySchemaMetadataArgs>? Metadata { get; set; }

        /// <summary>
        /// (Updatable) The object's type.
        /// </summary>
        [Input("modelType", required: true)]
        public Input<string> ModelType { get; set; } = null!;

        /// <summary>
        /// (Updatable) The object's model version.
        /// </summary>
        [Input("modelVersion")]
        public Input<string>? ModelVersion { get; set; }

        /// <summary>
        /// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        /// <summary>
        /// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
        /// </summary>
        [Input("objectStatus")]
        public Input<int>? ObjectStatus { get; set; }

        /// <summary>
        /// (Updatable) The version of the object that is used to track changes in the object instance.
        /// </summary>
        [Input("objectVersion")]
        public Input<int>? ObjectVersion { get; set; }

        /// <summary>
        /// (Updatable) A reference to the object's parent.
        /// </summary>
        [Input("parentRef")]
        public Input<Inputs.RegistryConnectionPrimarySchemaParentRefArgs>? ParentRef { get; set; }

        /// <summary>
        /// (Updatable) A resource name can have letters, numbers, and special characters. The value is editable and is restricted to 4000 characters.
        /// </summary>
        [Input("resourceName")]
        public Input<string>? ResourceName { get; set; }

        public RegistryConnectionPrimarySchemaArgs()
        {
        }
        public static new RegistryConnectionPrimarySchemaArgs Empty => new RegistryConnectionPrimarySchemaArgs();
    }
}