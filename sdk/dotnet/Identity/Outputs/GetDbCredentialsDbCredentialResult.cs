// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetDbCredentialsDbCredentialResult
    {
        /// <summary>
        /// The description you assign to the DB credential. Does not have to be unique, and it's changeable.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The OCID of the DB credential.
        /// </summary>
        public readonly string Id;
        public readonly string LifecycleDetails;
        public readonly string Password;
        /// <summary>
        /// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Date and time the `DbCredential` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Date and time when this credential will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeExpires;
        /// <summary>
        /// The OCID of the user.
        /// </summary>
        public readonly string UserId;

        [OutputConstructor]
        private GetDbCredentialsDbCredentialResult(
            string description,

            string id,

            string lifecycleDetails,

            string password,

            string state,

            string timeCreated,

            string timeExpires,

            string userId)
        {
            Description = description;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            Password = password;
            State = state;
            TimeCreated = timeCreated;
            TimeExpires = timeExpires;
            UserId = userId;
        }
    }
}