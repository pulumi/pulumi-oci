// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataCatalog.Inputs
{

    public sealed class CatalogPrivateEndpointLockGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// A message added by the creator of the lock. This is typically used to give an indication of why the resource is locked.
        /// </summary>
        [Input("message")]
        public Input<string>? Message { get; set; }

        /// <summary>
        /// The id of the resource that is locking this resource. Indicates that deleting this resource will remove the lock.
        /// </summary>
        [Input("relatedResourceId")]
        public Input<string>? RelatedResourceId { get; set; }

        /// <summary>
        /// The time the private endpoint was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// Type of the lock.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public CatalogPrivateEndpointLockGetArgs()
        {
        }
        public static new CatalogPrivateEndpointLockGetArgs Empty => new CatalogPrivateEndpointLockGetArgs();
    }
}
