// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetSqlFirewallPolicyResult {
    /**
     * @return The list of allowed ip addresses for the SQL firewall policy.
     * 
     */
    private List<String> allowedClientIps;
    /**
     * @return The list of allowed operating system user names for the SQL firewall policy.
     * 
     */
    private List<String> allowedClientOsUsernames;
    /**
     * @return The list of allowed client programs for the SQL firewall policy.
     * 
     */
    private List<String> allowedClientPrograms;
    /**
     * @return The OCID of the compartment containing the SQL firewall policy.
     * 
     */
    private String compartmentId;
    /**
     * @return The database user name.
     * 
     */
    private String dbUserName;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return The description of the SQL firewall policy.
     * 
     */
    private String description;
    /**
     * @return The display name of the SQL firewall policy.
     * 
     */
    private String displayName;
    /**
     * @return Specifies the SQL firewall policy enforcement option.
     * 
     */
    private String enforcementScope;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return The OCID of the SQL firewall policy.
     * 
     */
    private String id;
    /**
     * @return Details about the current state of the SQL firewall policy in Data Safe.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The OCID of the security policy corresponding to the SQL firewall policy.
     * 
     */
    private String securityPolicyId;
    private String sqlFirewallPolicyId;
    /**
     * @return Specifies the level of SQL included for this SQL firewall policy. USER_ISSUED_SQL - User issued SQL statements only. ALL_SQL - Includes all SQL statements including SQL statement issued inside PL/SQL units.
     * 
     */
    private String sqlLevel;
    /**
     * @return The current state of the SQL firewall policy.
     * 
     */
    private String state;
    /**
     * @return Specifies whether the SQL firewall policy is enabled or disabled.
     * 
     */
    private String status;
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    private Map<String,Object> systemTags;
    /**
     * @return The time that the SQL firewall policy was created, in the format defined by RFC3339.
     * 
     */
    private String timeCreated;
    /**
     * @return The date and time the SQL firewall policy was last updated, in the format defined by RFC3339.
     * 
     */
    private String timeUpdated;
    /**
     * @return Specifies the mode in which the SQL firewall policy is enabled.
     * 
     */
    private String violationAction;
    /**
     * @return Specifies whether a unified audit policy should be enabled for auditing the SQL firewall policy violations.
     * 
     */
    private String violationAudit;

    private GetSqlFirewallPolicyResult() {}
    /**
     * @return The list of allowed ip addresses for the SQL firewall policy.
     * 
     */
    public List<String> allowedClientIps() {
        return this.allowedClientIps;
    }
    /**
     * @return The list of allowed operating system user names for the SQL firewall policy.
     * 
     */
    public List<String> allowedClientOsUsernames() {
        return this.allowedClientOsUsernames;
    }
    /**
     * @return The list of allowed client programs for the SQL firewall policy.
     * 
     */
    public List<String> allowedClientPrograms() {
        return this.allowedClientPrograms;
    }
    /**
     * @return The OCID of the compartment containing the SQL firewall policy.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The database user name.
     * 
     */
    public String dbUserName() {
        return this.dbUserName;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The description of the SQL firewall policy.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The display name of the SQL firewall policy.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Specifies the SQL firewall policy enforcement option.
     * 
     */
    public String enforcementScope() {
        return this.enforcementScope;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the SQL firewall policy.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Details about the current state of the SQL firewall policy in Data Safe.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The OCID of the security policy corresponding to the SQL firewall policy.
     * 
     */
    public String securityPolicyId() {
        return this.securityPolicyId;
    }
    public String sqlFirewallPolicyId() {
        return this.sqlFirewallPolicyId;
    }
    /**
     * @return Specifies the level of SQL included for this SQL firewall policy. USER_ISSUED_SQL - User issued SQL statements only. ALL_SQL - Includes all SQL statements including SQL statement issued inside PL/SQL units.
     * 
     */
    public String sqlLevel() {
        return this.sqlLevel;
    }
    /**
     * @return The current state of the SQL firewall policy.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Specifies whether the SQL firewall policy is enabled or disabled.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Map<String,Object> systemTags() {
        return this.systemTags;
    }
    /**
     * @return The time that the SQL firewall policy was created, in the format defined by RFC3339.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The date and time the SQL firewall policy was last updated, in the format defined by RFC3339.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return Specifies the mode in which the SQL firewall policy is enabled.
     * 
     */
    public String violationAction() {
        return this.violationAction;
    }
    /**
     * @return Specifies whether a unified audit policy should be enabled for auditing the SQL firewall policy violations.
     * 
     */
    public String violationAudit() {
        return this.violationAudit;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSqlFirewallPolicyResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> allowedClientIps;
        private List<String> allowedClientOsUsernames;
        private List<String> allowedClientPrograms;
        private String compartmentId;
        private String dbUserName;
        private Map<String,Object> definedTags;
        private String description;
        private String displayName;
        private String enforcementScope;
        private Map<String,Object> freeformTags;
        private String id;
        private String lifecycleDetails;
        private String securityPolicyId;
        private String sqlFirewallPolicyId;
        private String sqlLevel;
        private String state;
        private String status;
        private Map<String,Object> systemTags;
        private String timeCreated;
        private String timeUpdated;
        private String violationAction;
        private String violationAudit;
        public Builder() {}
        public Builder(GetSqlFirewallPolicyResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allowedClientIps = defaults.allowedClientIps;
    	      this.allowedClientOsUsernames = defaults.allowedClientOsUsernames;
    	      this.allowedClientPrograms = defaults.allowedClientPrograms;
    	      this.compartmentId = defaults.compartmentId;
    	      this.dbUserName = defaults.dbUserName;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.enforcementScope = defaults.enforcementScope;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.securityPolicyId = defaults.securityPolicyId;
    	      this.sqlFirewallPolicyId = defaults.sqlFirewallPolicyId;
    	      this.sqlLevel = defaults.sqlLevel;
    	      this.state = defaults.state;
    	      this.status = defaults.status;
    	      this.systemTags = defaults.systemTags;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.violationAction = defaults.violationAction;
    	      this.violationAudit = defaults.violationAudit;
        }

        @CustomType.Setter
        public Builder allowedClientIps(List<String> allowedClientIps) {
            this.allowedClientIps = Objects.requireNonNull(allowedClientIps);
            return this;
        }
        public Builder allowedClientIps(String... allowedClientIps) {
            return allowedClientIps(List.of(allowedClientIps));
        }
        @CustomType.Setter
        public Builder allowedClientOsUsernames(List<String> allowedClientOsUsernames) {
            this.allowedClientOsUsernames = Objects.requireNonNull(allowedClientOsUsernames);
            return this;
        }
        public Builder allowedClientOsUsernames(String... allowedClientOsUsernames) {
            return allowedClientOsUsernames(List.of(allowedClientOsUsernames));
        }
        @CustomType.Setter
        public Builder allowedClientPrograms(List<String> allowedClientPrograms) {
            this.allowedClientPrograms = Objects.requireNonNull(allowedClientPrograms);
            return this;
        }
        public Builder allowedClientPrograms(String... allowedClientPrograms) {
            return allowedClientPrograms(List.of(allowedClientPrograms));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder dbUserName(String dbUserName) {
            this.dbUserName = Objects.requireNonNull(dbUserName);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder enforcementScope(String enforcementScope) {
            this.enforcementScope = Objects.requireNonNull(enforcementScope);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder securityPolicyId(String securityPolicyId) {
            this.securityPolicyId = Objects.requireNonNull(securityPolicyId);
            return this;
        }
        @CustomType.Setter
        public Builder sqlFirewallPolicyId(String sqlFirewallPolicyId) {
            this.sqlFirewallPolicyId = Objects.requireNonNull(sqlFirewallPolicyId);
            return this;
        }
        @CustomType.Setter
        public Builder sqlLevel(String sqlLevel) {
            this.sqlLevel = Objects.requireNonNull(sqlLevel);
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            this.status = Objects.requireNonNull(status);
            return this;
        }
        @CustomType.Setter
        public Builder systemTags(Map<String,Object> systemTags) {
            this.systemTags = Objects.requireNonNull(systemTags);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        @CustomType.Setter
        public Builder violationAction(String violationAction) {
            this.violationAction = Objects.requireNonNull(violationAction);
            return this;
        }
        @CustomType.Setter
        public Builder violationAudit(String violationAudit) {
            this.violationAudit = Objects.requireNonNull(violationAudit);
            return this;
        }
        public GetSqlFirewallPolicyResult build() {
            final var o = new GetSqlFirewallPolicyResult();
            o.allowedClientIps = allowedClientIps;
            o.allowedClientOsUsernames = allowedClientOsUsernames;
            o.allowedClientPrograms = allowedClientPrograms;
            o.compartmentId = compartmentId;
            o.dbUserName = dbUserName;
            o.definedTags = definedTags;
            o.description = description;
            o.displayName = displayName;
            o.enforcementScope = enforcementScope;
            o.freeformTags = freeformTags;
            o.id = id;
            o.lifecycleDetails = lifecycleDetails;
            o.securityPolicyId = securityPolicyId;
            o.sqlFirewallPolicyId = sqlFirewallPolicyId;
            o.sqlLevel = sqlLevel;
            o.state = state;
            o.status = status;
            o.systemTags = systemTags;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            o.violationAction = violationAction;
            o.violationAudit = violationAudit;
            return o;
        }
    }
}