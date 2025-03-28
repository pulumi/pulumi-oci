// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseUserRolesRoleCollectionItem {
    /**
     * @return Indicates whether the role is granted with the ADMIN OPTION (YES) or not (NO).
     * 
     */
    private String adminOption;
    /**
     * @return Indicates how the role was granted. Possible values: YES if the role is granted commonly (CONTAINER=ALL is used) NO if the role is granted locally (CONTAINER=ALL is not used)
     * 
     */
    private String common;
    /**
     * @return Indicates whether the role is designated as a DEFAULT ROLE for the user (YES) or not (NO).
     * 
     */
    private String defaultRole;
    /**
     * @return Indicates whether the role is granted with the DELEGATE OPTION (YES) or not (NO).
     * 
     */
    private String delegateOption;
    /**
     * @return Indicates whether the granted role is inherited from another container (YES) or not (NO).
     * 
     */
    private String inherited;
    /**
     * @return A filter to return only resources that match the entire name.
     * 
     */
    private String name;

    private GetManagedDatabaseUserRolesRoleCollectionItem() {}
    /**
     * @return Indicates whether the role is granted with the ADMIN OPTION (YES) or not (NO).
     * 
     */
    public String adminOption() {
        return this.adminOption;
    }
    /**
     * @return Indicates how the role was granted. Possible values: YES if the role is granted commonly (CONTAINER=ALL is used) NO if the role is granted locally (CONTAINER=ALL is not used)
     * 
     */
    public String common() {
        return this.common;
    }
    /**
     * @return Indicates whether the role is designated as a DEFAULT ROLE for the user (YES) or not (NO).
     * 
     */
    public String defaultRole() {
        return this.defaultRole;
    }
    /**
     * @return Indicates whether the role is granted with the DELEGATE OPTION (YES) or not (NO).
     * 
     */
    public String delegateOption() {
        return this.delegateOption;
    }
    /**
     * @return Indicates whether the granted role is inherited from another container (YES) or not (NO).
     * 
     */
    public String inherited() {
        return this.inherited;
    }
    /**
     * @return A filter to return only resources that match the entire name.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseUserRolesRoleCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String adminOption;
        private String common;
        private String defaultRole;
        private String delegateOption;
        private String inherited;
        private String name;
        public Builder() {}
        public Builder(GetManagedDatabaseUserRolesRoleCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adminOption = defaults.adminOption;
    	      this.common = defaults.common;
    	      this.defaultRole = defaults.defaultRole;
    	      this.delegateOption = defaults.delegateOption;
    	      this.inherited = defaults.inherited;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder adminOption(String adminOption) {
            if (adminOption == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseUserRolesRoleCollectionItem", "adminOption");
            }
            this.adminOption = adminOption;
            return this;
        }
        @CustomType.Setter
        public Builder common(String common) {
            if (common == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseUserRolesRoleCollectionItem", "common");
            }
            this.common = common;
            return this;
        }
        @CustomType.Setter
        public Builder defaultRole(String defaultRole) {
            if (defaultRole == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseUserRolesRoleCollectionItem", "defaultRole");
            }
            this.defaultRole = defaultRole;
            return this;
        }
        @CustomType.Setter
        public Builder delegateOption(String delegateOption) {
            if (delegateOption == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseUserRolesRoleCollectionItem", "delegateOption");
            }
            this.delegateOption = delegateOption;
            return this;
        }
        @CustomType.Setter
        public Builder inherited(String inherited) {
            if (inherited == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseUserRolesRoleCollectionItem", "inherited");
            }
            this.inherited = inherited;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseUserRolesRoleCollectionItem", "name");
            }
            this.name = name;
            return this;
        }
        public GetManagedDatabaseUserRolesRoleCollectionItem build() {
            final var _resultValue = new GetManagedDatabaseUserRolesRoleCollectionItem();
            _resultValue.adminOption = adminOption;
            _resultValue.common = common;
            _resultValue.defaultRole = defaultRole;
            _resultValue.delegateOption = delegateOption;
            _resultValue.inherited = inherited;
            _resultValue.name = name;
            return _resultValue;
        }
    }
}
