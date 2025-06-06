// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OneSubsription.Outputs
{

    [OutputType]
    public sealed class GetSubscribedServicesSubscribedServicePaymentTermResult
    {
        /// <summary>
        /// User that created the Payment term
        /// </summary>
        public readonly string CreatedBy;
        /// <summary>
        /// Payment term Description
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Payment term active flag
        /// </summary>
        public readonly bool IsActive;
        /// <summary>
        /// Commercial name also called customer name.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Subscribed service creation date
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Subscribed service last update date
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// User that updated the subscribed service
        /// </summary>
        public readonly string UpdatedBy;
        /// <summary>
        /// Payment Term value
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetSubscribedServicesSubscribedServicePaymentTermResult(
            string createdBy,

            string description,

            bool isActive,

            string name,

            string timeCreated,

            string timeUpdated,

            string updatedBy,

            string value)
        {
            CreatedBy = createdBy;
            Description = description;
            IsActive = isActive;
            Name = name;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            UpdatedBy = updatedBy;
            Value = value;
        }
    }
}
