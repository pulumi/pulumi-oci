// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetSecurityPolicyReportDatabaseTableAccessEntriesDatabaseTableAccessEntryCollectionItemResult
    {
        /// <summary>
        /// A non-null value in this field indicates the object through which user has access to table, possible values could be table or view.
        /// </summary>
        public readonly string AccessThroughObject;
        /// <summary>
        /// The type of the access the user has on the table, there can be one or more from SELECT, UPDATE, INSERT, OWNER or DELETE.
        /// </summary>
        public readonly string AccessType;
        /// <summary>
        /// Indicates whether the user has access to all the tables in the schema.
        /// </summary>
        public readonly bool AreAllTablesAccessible;
        /// <summary>
        /// If there are column level privileges on a table or view.
        /// </summary>
        public readonly string ColumnName;
        /// <summary>
        /// This can be empty in case of direct grant, in case of indirect grant, this attribute displays the name of the  role which is granted to the user though which the user has access to the table.
        /// </summary>
        public readonly string GrantFromRole;
        /// <summary>
        /// Grantee is the user who can access the table
        /// </summary>
        public readonly string Grantee;
        /// <summary>
        /// The one who granted this privilege.
        /// </summary>
        public readonly string Grantor;
        /// <summary>
        /// Indicates whether the table access is constrained via Oracle Database Vault.
        /// </summary>
        public readonly bool IsAccessConstrainedByDatabaseVault;
        /// <summary>
        /// Indicates whether the table access is constrained via Oracle Label Security.
        /// </summary>
        public readonly bool IsAccessConstrainedByLabelSecurity;
        /// <summary>
        /// Indicates whether the table access is constrained via Real Application Security.
        /// </summary>
        public readonly bool IsAccessConstrainedByRealApplicationSecurity;
        /// <summary>
        /// Indicates whether the table access is constrained via Oracle Data Redaction.
        /// </summary>
        public readonly bool IsAccessConstrainedByRedaction;
        /// <summary>
        /// Indicates whether the table access is constrained via Oracle Database SQL Firewall.
        /// </summary>
        public readonly bool IsAccessConstrainedBySqlFirewall;
        /// <summary>
        /// Indicates whether the access is constrained on a table via a view.
        /// </summary>
        public readonly bool IsAccessConstrainedByView;
        /// <summary>
        /// Indicates whether the table access is constrained via Virtual Private Database.
        /// </summary>
        public readonly bool IsAccessConstrainedByVirtualPrivateDatabase;
        /// <summary>
        /// Indicates whether the table is marked as sensitive.
        /// </summary>
        public readonly bool IsSensitive;
        /// <summary>
        /// The unique key that identifies the table access report. It is numeric and unique within a security policy report.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// Name of the privilege.
        /// </summary>
        public readonly string Privilege;
        /// <summary>
        /// Indicates whether the grantee can grant this privilege to other users. Privileges can be granted to a user or role with  GRANT_OPTION or ADMIN_OPTION
        /// </summary>
        public readonly string PrivilegeGrantable;
        /// <summary>
        /// Type of the privilege user has, this includes System Privilege, Schema Privilege, Object Privilege, Column Privilege, Owner or Schema Privilege on a schema.
        /// </summary>
        public readonly string PrivilegeType;
        /// <summary>
        /// The name of the database table the user has access to.
        /// </summary>
        public readonly string TableName;
        /// <summary>
        /// The name of the schema the table belongs to.
        /// </summary>
        public readonly string TableSchema;
        /// <summary>
        /// The OCID of the of the  target database.
        /// </summary>
        public readonly string TargetId;

        [OutputConstructor]
        private GetSecurityPolicyReportDatabaseTableAccessEntriesDatabaseTableAccessEntryCollectionItemResult(
            string accessThroughObject,

            string accessType,

            bool areAllTablesAccessible,

            string columnName,

            string grantFromRole,

            string grantee,

            string grantor,

            bool isAccessConstrainedByDatabaseVault,

            bool isAccessConstrainedByLabelSecurity,

            bool isAccessConstrainedByRealApplicationSecurity,

            bool isAccessConstrainedByRedaction,

            bool isAccessConstrainedBySqlFirewall,

            bool isAccessConstrainedByView,

            bool isAccessConstrainedByVirtualPrivateDatabase,

            bool isSensitive,

            string key,

            string privilege,

            string privilegeGrantable,

            string privilegeType,

            string tableName,

            string tableSchema,

            string targetId)
        {
            AccessThroughObject = accessThroughObject;
            AccessType = accessType;
            AreAllTablesAccessible = areAllTablesAccessible;
            ColumnName = columnName;
            GrantFromRole = grantFromRole;
            Grantee = grantee;
            Grantor = grantor;
            IsAccessConstrainedByDatabaseVault = isAccessConstrainedByDatabaseVault;
            IsAccessConstrainedByLabelSecurity = isAccessConstrainedByLabelSecurity;
            IsAccessConstrainedByRealApplicationSecurity = isAccessConstrainedByRealApplicationSecurity;
            IsAccessConstrainedByRedaction = isAccessConstrainedByRedaction;
            IsAccessConstrainedBySqlFirewall = isAccessConstrainedBySqlFirewall;
            IsAccessConstrainedByView = isAccessConstrainedByView;
            IsAccessConstrainedByVirtualPrivateDatabase = isAccessConstrainedByVirtualPrivateDatabase;
            IsSensitive = isSensitive;
            Key = key;
            Privilege = privilege;
            PrivilegeGrantable = privilegeGrantable;
            PrivilegeType = privilegeType;
            TableName = tableName;
            TableSchema = tableSchema;
            TargetId = targetId;
        }
    }
}
