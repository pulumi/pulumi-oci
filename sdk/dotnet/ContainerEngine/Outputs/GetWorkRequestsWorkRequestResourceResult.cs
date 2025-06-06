// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class GetWorkRequestsWorkRequestResourceResult
    {
        /// <summary>
        /// The way in which this resource was affected by the work tracked by the work request.
        /// </summary>
        public readonly string ActionType;
        /// <summary>
        /// The resource type the work request affects.
        /// </summary>
        public readonly string EntityType;
        /// <summary>
        /// The URI path on which the user can issue a GET request to access the resource metadata.
        /// </summary>
        public readonly string EntityUri;
        /// <summary>
        /// The OCID of the resource the work request affects.
        /// </summary>
        public readonly string Identifier;

        [OutputConstructor]
        private GetWorkRequestsWorkRequestResourceResult(
            string actionType,

            string entityType,

            string entityUri,

            string identifier)
        {
            ActionType = actionType;
            EntityType = entityType;
            EntityUri = entityUri;
            Identifier = identifier;
        }
    }
}
