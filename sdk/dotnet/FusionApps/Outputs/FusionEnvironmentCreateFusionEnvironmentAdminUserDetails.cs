// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FusionApps.Outputs
{

    [OutputType]
    public sealed class FusionEnvironmentCreateFusionEnvironmentAdminUserDetails
    {
        /// <summary>
        /// The email address for the administrator.
        /// </summary>
        public readonly string EmailAddress;
        /// <summary>
        /// The administrator's first name.
        /// </summary>
        public readonly string FirstName;
        /// <summary>
        /// The administrator's last name.
        /// </summary>
        public readonly string LastName;
        /// <summary>
        /// The password for the administrator.
        /// </summary>
        public readonly string? Password;
        /// <summary>
        /// The username for the administrator.
        /// </summary>
        public readonly string Username;

        [OutputConstructor]
        private FusionEnvironmentCreateFusionEnvironmentAdminUserDetails(
            string emailAddress,

            string firstName,

            string lastName,

            string? password,

            string username)
        {
            EmailAddress = emailAddress;
            FirstName = firstName;
            LastName = lastName;
            Password = password;
            Username = username;
        }
    }
}
