// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetTargetDatabaseRolesRole {
    /**
     * @return A filter to return roles based on authentication type.
     * 
     */
    private String authenticationType;
    /**
     * @return Is the role common.
     * 
     */
    private Boolean isCommon;
    /**
     * @return Is the role implicit.
     * 
     */
    private Boolean isImplicit;
    /**
     * @return Is the role inherited.
     * 
     */
    private Boolean isInherited;
    /**
     * @return A filter to return roles based on whether they are maintained by oracle or not.
     * 
     */
    private Boolean isOracleMaintained;
    /**
     * @return Is password required.
     * 
     */
    private Boolean isPasswordRequired;
    /**
     * @return A filter to return only a specific role based on role name.
     * 
     */
    private String roleName;

    private GetTargetDatabaseRolesRole() {}
    /**
     * @return A filter to return roles based on authentication type.
     * 
     */
    public String authenticationType() {
        return this.authenticationType;
    }
    /**
     * @return Is the role common.
     * 
     */
    public Boolean isCommon() {
        return this.isCommon;
    }
    /**
     * @return Is the role implicit.
     * 
     */
    public Boolean isImplicit() {
        return this.isImplicit;
    }
    /**
     * @return Is the role inherited.
     * 
     */
    public Boolean isInherited() {
        return this.isInherited;
    }
    /**
     * @return A filter to return roles based on whether they are maintained by oracle or not.
     * 
     */
    public Boolean isOracleMaintained() {
        return this.isOracleMaintained;
    }
    /**
     * @return Is password required.
     * 
     */
    public Boolean isPasswordRequired() {
        return this.isPasswordRequired;
    }
    /**
     * @return A filter to return only a specific role based on role name.
     * 
     */
    public String roleName() {
        return this.roleName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTargetDatabaseRolesRole defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String authenticationType;
        private Boolean isCommon;
        private Boolean isImplicit;
        private Boolean isInherited;
        private Boolean isOracleMaintained;
        private Boolean isPasswordRequired;
        private String roleName;
        public Builder() {}
        public Builder(GetTargetDatabaseRolesRole defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.authenticationType = defaults.authenticationType;
    	      this.isCommon = defaults.isCommon;
    	      this.isImplicit = defaults.isImplicit;
    	      this.isInherited = defaults.isInherited;
    	      this.isOracleMaintained = defaults.isOracleMaintained;
    	      this.isPasswordRequired = defaults.isPasswordRequired;
    	      this.roleName = defaults.roleName;
        }

        @CustomType.Setter
        public Builder authenticationType(String authenticationType) {
            this.authenticationType = Objects.requireNonNull(authenticationType);
            return this;
        }
        @CustomType.Setter
        public Builder isCommon(Boolean isCommon) {
            this.isCommon = Objects.requireNonNull(isCommon);
            return this;
        }
        @CustomType.Setter
        public Builder isImplicit(Boolean isImplicit) {
            this.isImplicit = Objects.requireNonNull(isImplicit);
            return this;
        }
        @CustomType.Setter
        public Builder isInherited(Boolean isInherited) {
            this.isInherited = Objects.requireNonNull(isInherited);
            return this;
        }
        @CustomType.Setter
        public Builder isOracleMaintained(Boolean isOracleMaintained) {
            this.isOracleMaintained = Objects.requireNonNull(isOracleMaintained);
            return this;
        }
        @CustomType.Setter
        public Builder isPasswordRequired(Boolean isPasswordRequired) {
            this.isPasswordRequired = Objects.requireNonNull(isPasswordRequired);
            return this;
        }
        @CustomType.Setter
        public Builder roleName(String roleName) {
            this.roleName = Objects.requireNonNull(roleName);
            return this;
        }
        public GetTargetDatabaseRolesRole build() {
            final var o = new GetTargetDatabaseRolesRole();
            o.authenticationType = authenticationType;
            o.isCommon = isCommon;
            o.isImplicit = isImplicit;
            o.isInherited = isInherited;
            o.isOracleMaintained = isOracleMaintained;
            o.isPasswordRequired = isPasswordRequired;
            o.roleName = roleName;
            return o;
        }
    }
}