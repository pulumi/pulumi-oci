// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetManagedDatabaseUsersUserCollectionItemResult
    {
        /// <summary>
        /// In a sharded database, indicates whether the user is created with shard DDL enabled (YES) or not (NO).
        /// </summary>
        public readonly string AllShared;
        /// <summary>
        /// The authentication mechanism for the user.
        /// </summary>
        public readonly string Authentication;
        /// <summary>
        /// Indicates whether a given user is common(Y) or local(N).
        /// </summary>
        public readonly string Common;
        /// <summary>
        /// The initial resource consumer group for the User.
        /// </summary>
        public readonly string ConsumerGroup;
        /// <summary>
        /// The default collation for the user schema.
        /// </summary>
        public readonly string DefaultCollation;
        /// <summary>
        /// The default tablespace for data.
        /// </summary>
        public readonly string DefaultTablespace;
        /// <summary>
        /// Indicates whether editions have been enabled for the corresponding user (Y) or not (N).
        /// </summary>
        public readonly string EditionsEnabled;
        /// <summary>
        /// The external name of the user.
        /// </summary>
        public readonly string ExternalName;
        /// <summary>
        /// In a federated sharded database, indicates whether the user is an external shard user (YES) or not (NO).
        /// </summary>
        public readonly string ExternalShared;
        /// <summary>
        /// Indicates whether the user is a common user created by an implicit application (YES) or not (NO).
        /// </summary>
        public readonly string Implicit;
        /// <summary>
        /// Indicates whether the user definition is inherited from another container (YES) or not (NO).
        /// </summary>
        public readonly string Inherited;
        /// <summary>
        /// The default local temporary tablespace for the user.
        /// </summary>
        public readonly string LocalTempTablespace;
        /// <summary>
        /// A filter to return only resources that match the entire name.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Indicates whether the user was created and is maintained by Oracle-supplied scripts (such as catalog.sql or catproc.sql).
        /// </summary>
        public readonly string OracleMaintained;
        /// <summary>
        /// The list of existing versions of the password hashes (also known as "verifiers") for the account.
        /// </summary>
        public readonly string PasswordVersions;
        /// <summary>
        /// The profile name of the user.
        /// </summary>
        public readonly string Profile;
        /// <summary>
        /// Indicates whether a user can connect directly (N) or whether the account can only be proxied (Y) by users who have proxy privileges for this account (that is, by users who have been granted the "connect through" privilege for this account).
        /// </summary>
        public readonly string ProxyConnect;
        /// <summary>
        /// The status of the user account.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The name of the default tablespace for temporary tables or the name of a tablespace group.
        /// </summary>
        public readonly string TempTablespace;
        /// <summary>
        /// The date and time the user was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time of the expiration of the user account.
        /// </summary>
        public readonly string TimeExpiring;
        /// <summary>
        /// The date and time of the last user login. This column is not populated when a user connects to the database with administrative privileges, that is, AS { SYSASM | SYSBACKUP | SYSDBA | SYSDG | SYSOPER | SYSRAC | SYSKM }.
        /// </summary>
        public readonly string TimeLastLogin;
        /// <summary>
        /// The date the account was locked, if the status of the account is LOCKED.
        /// </summary>
        public readonly string TimeLocked;
        /// <summary>
        /// The date and time when the user password was last set. This column is populated only when the value of the AUTHENTICATION_TYPE column is PASSWORD. Otherwise, this column is null.
        /// </summary>
        public readonly string TimePasswordChanged;

        [OutputConstructor]
        private GetManagedDatabaseUsersUserCollectionItemResult(
            string allShared,

            string authentication,

            string common,

            string consumerGroup,

            string defaultCollation,

            string defaultTablespace,

            string editionsEnabled,

            string externalName,

            string externalShared,

            string @implicit,

            string inherited,

            string localTempTablespace,

            string name,

            string oracleMaintained,

            string passwordVersions,

            string profile,

            string proxyConnect,

            string status,

            string tempTablespace,

            string timeCreated,

            string timeExpiring,

            string timeLastLogin,

            string timeLocked,

            string timePasswordChanged)
        {
            AllShared = allShared;
            Authentication = authentication;
            Common = common;
            ConsumerGroup = consumerGroup;
            DefaultCollation = defaultCollation;
            DefaultTablespace = defaultTablespace;
            EditionsEnabled = editionsEnabled;
            ExternalName = externalName;
            ExternalShared = externalShared;
            Implicit = @implicit;
            Inherited = inherited;
            LocalTempTablespace = localTempTablespace;
            Name = name;
            OracleMaintained = oracleMaintained;
            PasswordVersions = passwordVersions;
            Profile = profile;
            ProxyConnect = proxyConnect;
            Status = status;
            TempTablespace = tempTablespace;
            TimeCreated = timeCreated;
            TimeExpiring = timeExpiring;
            TimeLastLogin = timeLastLogin;
            TimeLocked = timeLocked;
            TimePasswordChanged = timePasswordChanged;
        }
    }
}