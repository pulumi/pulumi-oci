// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupAppRole;
import com.pulumi.oci.Identity.outputs.GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant;
import com.pulumi.oci.Identity.outputs.GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupOwner;
import com.pulumi.oci.Identity.outputs.GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupPasswordPolicy;
import com.pulumi.oci.Identity.outputs.GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromApp;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup {
    /**
     * @return A list of appRoles that the user belongs to, either thorough direct membership, nested groups, or dynamically calculated
     * 
     */
    private List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupAppRole> appRoles;
    /**
     * @return Source from which this group got created.
     * 
     */
    private String creationMechanism;
    /**
     * @return Group description
     * 
     */
    private String description;
    /**
     * @return Grants assigned to group
     * 
     */
    private List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant> grants;
    /**
     * @return Group owners
     * 
     */
    private List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupOwner> owners;
    /**
     * @return Password Policy associated with this Group.
     * 
     */
    private List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupPasswordPolicy> passwordPolicies;
    /**
     * @return The entity that created this Group.
     * 
     */
    private List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromApp> syncedFromApps;

    private GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup() {}
    /**
     * @return A list of appRoles that the user belongs to, either thorough direct membership, nested groups, or dynamically calculated
     * 
     */
    public List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupAppRole> appRoles() {
        return this.appRoles;
    }
    /**
     * @return Source from which this group got created.
     * 
     */
    public String creationMechanism() {
        return this.creationMechanism;
    }
    /**
     * @return Group description
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Grants assigned to group
     * 
     */
    public List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant> grants() {
        return this.grants;
    }
    /**
     * @return Group owners
     * 
     */
    public List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupOwner> owners() {
        return this.owners;
    }
    /**
     * @return Password Policy associated with this Group.
     * 
     */
    public List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupPasswordPolicy> passwordPolicies() {
        return this.passwordPolicies;
    }
    /**
     * @return The entity that created this Group.
     * 
     */
    public List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromApp> syncedFromApps() {
        return this.syncedFromApps;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupAppRole> appRoles;
        private String creationMechanism;
        private String description;
        private List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant> grants;
        private List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupOwner> owners;
        private List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupPasswordPolicy> passwordPolicies;
        private List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromApp> syncedFromApps;
        public Builder() {}
        public Builder(GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.appRoles = defaults.appRoles;
    	      this.creationMechanism = defaults.creationMechanism;
    	      this.description = defaults.description;
    	      this.grants = defaults.grants;
    	      this.owners = defaults.owners;
    	      this.passwordPolicies = defaults.passwordPolicies;
    	      this.syncedFromApps = defaults.syncedFromApps;
        }

        @CustomType.Setter
        public Builder appRoles(List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupAppRole> appRoles) {
            if (appRoles == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup", "appRoles");
            }
            this.appRoles = appRoles;
            return this;
        }
        public Builder appRoles(GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupAppRole... appRoles) {
            return appRoles(List.of(appRoles));
        }
        @CustomType.Setter
        public Builder creationMechanism(String creationMechanism) {
            if (creationMechanism == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup", "creationMechanism");
            }
            this.creationMechanism = creationMechanism;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder grants(List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant> grants) {
            if (grants == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup", "grants");
            }
            this.grants = grants;
            return this;
        }
        public Builder grants(GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrant... grants) {
            return grants(List.of(grants));
        }
        @CustomType.Setter
        public Builder owners(List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupOwner> owners) {
            if (owners == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup", "owners");
            }
            this.owners = owners;
            return this;
        }
        public Builder owners(GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupOwner... owners) {
            return owners(List.of(owners));
        }
        @CustomType.Setter
        public Builder passwordPolicies(List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupPasswordPolicy> passwordPolicies) {
            if (passwordPolicies == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup", "passwordPolicies");
            }
            this.passwordPolicies = passwordPolicies;
            return this;
        }
        public Builder passwordPolicies(GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupPasswordPolicy... passwordPolicies) {
            return passwordPolicies(List.of(passwordPolicies));
        }
        @CustomType.Setter
        public Builder syncedFromApps(List<GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromApp> syncedFromApps) {
            if (syncedFromApps == null) {
              throw new MissingRequiredPropertyException("GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup", "syncedFromApps");
            }
            this.syncedFromApps = syncedFromApps;
            return this;
        }
        public Builder syncedFromApps(GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromApp... syncedFromApps) {
            return syncedFromApps(List.of(syncedFromApps));
        }
        public GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup build() {
            final var _resultValue = new GetDomainsMyRequestableGroupsMyRequestableGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroup();
            _resultValue.appRoles = appRoles;
            _resultValue.creationMechanism = creationMechanism;
            _resultValue.description = description;
            _resultValue.grants = grants;
            _resultValue.owners = owners;
            _resultValue.passwordPolicies = passwordPolicies;
            _resultValue.syncedFromApps = syncedFromApps;
            return _resultValue;
        }
    }
}
