// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetSqlFirewallAllowedSqlsSqlFirewallAllowedSqlCollectionItemResult
    {
        /// <summary>
        /// A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The name of the user that SQL was executed as.
        /// </summary>
        public readonly string CurrentUser;
        /// <summary>
        /// The database user name.
        /// </summary>
        public readonly string DbUserName;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The description of the SQL firewall allowed SQL.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The display name of the SQL firewall allowed SQL.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The OCID of the SQL firewall allowed SQL.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The objects accessed by the SQL.
        /// </summary>
        public readonly ImmutableArray<string> SqlAccessedObjects;
        /// <summary>
        /// The OCID of the SQL firewall policy corresponding to the SQL firewall allowed SQL.
        /// </summary>
        public readonly string SqlFirewallPolicyId;
        /// <summary>
        /// Specifies the level of SQL included for this SQL firewall policy. USER_ISSUED_SQL - User issued SQL statements only. ALL_SQL - Includes all SQL statements including SQL statement issued inside PL/SQL units.
        /// </summary>
        public readonly string SqlLevel;
        /// <summary>
        /// The SQL text of the SQL firewall allowed SQL.
        /// </summary>
        public readonly string SqlText;
        /// <summary>
        /// The current state of the SQL firewall allowed SQL.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The time the the SQL firewall allowed SQL was collected from the target database, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeCollected;
        /// <summary>
        /// The last date and time the SQL firewall allowed SQL was updated, in the format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Version of the associated SQL firewall policy. This identifies whether the allowed SQLs were added in the same batch or not.
        /// </summary>
        public readonly double Version;

        [OutputConstructor]
        private GetSqlFirewallAllowedSqlsSqlFirewallAllowedSqlCollectionItemResult(
            string compartmentId,

            string currentUser,

            string dbUserName,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            ImmutableArray<string> sqlAccessedObjects,

            string sqlFirewallPolicyId,

            string sqlLevel,

            string sqlText,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCollected,

            string timeUpdated,

            double version)
        {
            CompartmentId = compartmentId;
            CurrentUser = currentUser;
            DbUserName = dbUserName;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            SqlAccessedObjects = sqlAccessedObjects;
            SqlFirewallPolicyId = sqlFirewallPolicyId;
            SqlLevel = sqlLevel;
            SqlText = sqlText;
            State = state;
            SystemTags = systemTags;
            TimeCollected = timeCollected;
            TimeUpdated = timeUpdated;
            Version = version;
        }
    }
}