// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedDatabasesUserSystemPrivilegeItem {
    /**
     * @return Indicates whether the system privilege is granted with the ADMIN option (YES) or not (NO).
     * 
     */
    private String adminOption;
    /**
     * @return Indicates how the system privilege was granted. Possible values: YES if the system privilege is granted commonly (CONTAINER=ALL is used) NO if the system privilege is granted locally (CONTAINER=ALL is not used)
     * 
     */
    private String common;
    /**
     * @return Indicates whether the granted system privilege is inherited from another container (YES) or not (NO).
     * 
     */
    private String inherited;
    /**
     * @return A filter to return only resources that match the entire name.
     * 
     */
    private String name;

    private GetManagedDatabasesUserSystemPrivilegeItem() {}
    /**
     * @return Indicates whether the system privilege is granted with the ADMIN option (YES) or not (NO).
     * 
     */
    public String adminOption() {
        return this.adminOption;
    }
    /**
     * @return Indicates how the system privilege was granted. Possible values: YES if the system privilege is granted commonly (CONTAINER=ALL is used) NO if the system privilege is granted locally (CONTAINER=ALL is not used)
     * 
     */
    public String common() {
        return this.common;
    }
    /**
     * @return Indicates whether the granted system privilege is inherited from another container (YES) or not (NO).
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

    public static Builder builder(GetManagedDatabasesUserSystemPrivilegeItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String adminOption;
        private String common;
        private String inherited;
        private String name;
        public Builder() {}
        public Builder(GetManagedDatabasesUserSystemPrivilegeItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adminOption = defaults.adminOption;
    	      this.common = defaults.common;
    	      this.inherited = defaults.inherited;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder adminOption(String adminOption) {
            if (adminOption == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesUserSystemPrivilegeItem", "adminOption");
            }
            this.adminOption = adminOption;
            return this;
        }
        @CustomType.Setter
        public Builder common(String common) {
            if (common == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesUserSystemPrivilegeItem", "common");
            }
            this.common = common;
            return this;
        }
        @CustomType.Setter
        public Builder inherited(String inherited) {
            if (inherited == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesUserSystemPrivilegeItem", "inherited");
            }
            this.inherited = inherited;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabasesUserSystemPrivilegeItem", "name");
            }
            this.name = name;
            return this;
        }
        public GetManagedDatabasesUserSystemPrivilegeItem build() {
            final var _resultValue = new GetManagedDatabasesUserSystemPrivilegeItem();
            _resultValue.adminOption = adminOption;
            _resultValue.common = common;
            _resultValue.inherited = inherited;
            _resultValue.name = name;
            return _resultValue;
        }
    }
}
