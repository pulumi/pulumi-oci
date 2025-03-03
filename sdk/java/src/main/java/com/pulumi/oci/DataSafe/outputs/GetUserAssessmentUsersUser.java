// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetUserAssessmentUsersUser {
    /**
     * @return A filter to return only items that match the specified account status.
     * 
     */
    private String accountStatus;
    /**
     * @return The admin roles granted to the user.
     * 
     */
    private List<String> adminRoles;
    /**
     * @return A filter to return only items that match the criteria that all schemas can be accessed by a user.
     * 
     */
    private Boolean areAllSchemasAccessible;
    /**
     * @return A filter to return only items that match the specified authentication type.
     * 
     */
    private String authenticationType;
    /**
     * @return The unique user key. This is a system-generated identifier. Use ListUsers to get the user key for a user.
     * 
     */
    private String key;
    /**
     * @return A filter to return items that contain the specified schema list.
     * 
     */
    private List<String> schemaLists;
    /**
     * @return A filter to return only items related to a specific target OCID.
     * 
     */
    private String targetId;
    /**
     * @return The date and time the user last logged in, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private String timeLastLogin;
    /**
     * @return The date and time the user password was last changed, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private String timePasswordChanged;
    /**
     * @return The date and time the user&#39;s password will expire, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private String timePasswordExpiry;
    /**
     * @return The date and time the user was created in the database, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    private String timeUserCreated;
    /**
     * @return A filter to return only items that match the specified user category.
     * 
     */
    private String userCategory;
    /**
     * @return A filter to return only items that match the specified user name.
     * 
     */
    private String userName;
    /**
     * @return A filter to return only items that match the specified user profile.
     * 
     */
    private String userProfile;
    /**
     * @return The user type, which can be a combination of the following:
     * 
     */
    private List<String> userTypes;

    private GetUserAssessmentUsersUser() {}
    /**
     * @return A filter to return only items that match the specified account status.
     * 
     */
    public String accountStatus() {
        return this.accountStatus;
    }
    /**
     * @return The admin roles granted to the user.
     * 
     */
    public List<String> adminRoles() {
        return this.adminRoles;
    }
    /**
     * @return A filter to return only items that match the criteria that all schemas can be accessed by a user.
     * 
     */
    public Boolean areAllSchemasAccessible() {
        return this.areAllSchemasAccessible;
    }
    /**
     * @return A filter to return only items that match the specified authentication type.
     * 
     */
    public String authenticationType() {
        return this.authenticationType;
    }
    /**
     * @return The unique user key. This is a system-generated identifier. Use ListUsers to get the user key for a user.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return A filter to return items that contain the specified schema list.
     * 
     */
    public List<String> schemaLists() {
        return this.schemaLists;
    }
    /**
     * @return A filter to return only items related to a specific target OCID.
     * 
     */
    public String targetId() {
        return this.targetId;
    }
    /**
     * @return The date and time the user last logged in, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeLastLogin() {
        return this.timeLastLogin;
    }
    /**
     * @return The date and time the user password was last changed, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timePasswordChanged() {
        return this.timePasswordChanged;
    }
    /**
     * @return The date and time the user&#39;s password will expire, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timePasswordExpiry() {
        return this.timePasswordExpiry;
    }
    /**
     * @return The date and time the user was created in the database, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public String timeUserCreated() {
        return this.timeUserCreated;
    }
    /**
     * @return A filter to return only items that match the specified user category.
     * 
     */
    public String userCategory() {
        return this.userCategory;
    }
    /**
     * @return A filter to return only items that match the specified user name.
     * 
     */
    public String userName() {
        return this.userName;
    }
    /**
     * @return A filter to return only items that match the specified user profile.
     * 
     */
    public String userProfile() {
        return this.userProfile;
    }
    /**
     * @return The user type, which can be a combination of the following:
     * 
     */
    public List<String> userTypes() {
        return this.userTypes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetUserAssessmentUsersUser defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String accountStatus;
        private List<String> adminRoles;
        private Boolean areAllSchemasAccessible;
        private String authenticationType;
        private String key;
        private List<String> schemaLists;
        private String targetId;
        private String timeLastLogin;
        private String timePasswordChanged;
        private String timePasswordExpiry;
        private String timeUserCreated;
        private String userCategory;
        private String userName;
        private String userProfile;
        private List<String> userTypes;
        public Builder() {}
        public Builder(GetUserAssessmentUsersUser defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accountStatus = defaults.accountStatus;
    	      this.adminRoles = defaults.adminRoles;
    	      this.areAllSchemasAccessible = defaults.areAllSchemasAccessible;
    	      this.authenticationType = defaults.authenticationType;
    	      this.key = defaults.key;
    	      this.schemaLists = defaults.schemaLists;
    	      this.targetId = defaults.targetId;
    	      this.timeLastLogin = defaults.timeLastLogin;
    	      this.timePasswordChanged = defaults.timePasswordChanged;
    	      this.timePasswordExpiry = defaults.timePasswordExpiry;
    	      this.timeUserCreated = defaults.timeUserCreated;
    	      this.userCategory = defaults.userCategory;
    	      this.userName = defaults.userName;
    	      this.userProfile = defaults.userProfile;
    	      this.userTypes = defaults.userTypes;
        }

        @CustomType.Setter
        public Builder accountStatus(String accountStatus) {
            if (accountStatus == null) {
              throw new MissingRequiredPropertyException("GetUserAssessmentUsersUser", "accountStatus");
            }
            this.accountStatus = accountStatus;
            return this;
        }
        @CustomType.Setter
        public Builder adminRoles(List<String> adminRoles) {
            if (adminRoles == null) {
              throw new MissingRequiredPropertyException("GetUserAssessmentUsersUser", "adminRoles");
            }
            this.adminRoles = adminRoles;
            return this;
        }
        public Builder adminRoles(String... adminRoles) {
            return adminRoles(List.of(adminRoles));
        }
        @CustomType.Setter
        public Builder areAllSchemasAccessible(Boolean areAllSchemasAccessible) {
            if (areAllSchemasAccessible == null) {
              throw new MissingRequiredPropertyException("GetUserAssessmentUsersUser", "areAllSchemasAccessible");
            }
            this.areAllSchemasAccessible = areAllSchemasAccessible;
            return this;
        }
        @CustomType.Setter
        public Builder authenticationType(String authenticationType) {
            if (authenticationType == null) {
              throw new MissingRequiredPropertyException("GetUserAssessmentUsersUser", "authenticationType");
            }
            this.authenticationType = authenticationType;
            return this;
        }
        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetUserAssessmentUsersUser", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder schemaLists(List<String> schemaLists) {
            if (schemaLists == null) {
              throw new MissingRequiredPropertyException("GetUserAssessmentUsersUser", "schemaLists");
            }
            this.schemaLists = schemaLists;
            return this;
        }
        public Builder schemaLists(String... schemaLists) {
            return schemaLists(List.of(schemaLists));
        }
        @CustomType.Setter
        public Builder targetId(String targetId) {
            if (targetId == null) {
              throw new MissingRequiredPropertyException("GetUserAssessmentUsersUser", "targetId");
            }
            this.targetId = targetId;
            return this;
        }
        @CustomType.Setter
        public Builder timeLastLogin(String timeLastLogin) {
            if (timeLastLogin == null) {
              throw new MissingRequiredPropertyException("GetUserAssessmentUsersUser", "timeLastLogin");
            }
            this.timeLastLogin = timeLastLogin;
            return this;
        }
        @CustomType.Setter
        public Builder timePasswordChanged(String timePasswordChanged) {
            if (timePasswordChanged == null) {
              throw new MissingRequiredPropertyException("GetUserAssessmentUsersUser", "timePasswordChanged");
            }
            this.timePasswordChanged = timePasswordChanged;
            return this;
        }
        @CustomType.Setter
        public Builder timePasswordExpiry(String timePasswordExpiry) {
            if (timePasswordExpiry == null) {
              throw new MissingRequiredPropertyException("GetUserAssessmentUsersUser", "timePasswordExpiry");
            }
            this.timePasswordExpiry = timePasswordExpiry;
            return this;
        }
        @CustomType.Setter
        public Builder timeUserCreated(String timeUserCreated) {
            if (timeUserCreated == null) {
              throw new MissingRequiredPropertyException("GetUserAssessmentUsersUser", "timeUserCreated");
            }
            this.timeUserCreated = timeUserCreated;
            return this;
        }
        @CustomType.Setter
        public Builder userCategory(String userCategory) {
            if (userCategory == null) {
              throw new MissingRequiredPropertyException("GetUserAssessmentUsersUser", "userCategory");
            }
            this.userCategory = userCategory;
            return this;
        }
        @CustomType.Setter
        public Builder userName(String userName) {
            if (userName == null) {
              throw new MissingRequiredPropertyException("GetUserAssessmentUsersUser", "userName");
            }
            this.userName = userName;
            return this;
        }
        @CustomType.Setter
        public Builder userProfile(String userProfile) {
            if (userProfile == null) {
              throw new MissingRequiredPropertyException("GetUserAssessmentUsersUser", "userProfile");
            }
            this.userProfile = userProfile;
            return this;
        }
        @CustomType.Setter
        public Builder userTypes(List<String> userTypes) {
            if (userTypes == null) {
              throw new MissingRequiredPropertyException("GetUserAssessmentUsersUser", "userTypes");
            }
            this.userTypes = userTypes;
            return this;
        }
        public Builder userTypes(String... userTypes) {
            return userTypes(List.of(userTypes));
        }
        public GetUserAssessmentUsersUser build() {
            final var _resultValue = new GetUserAssessmentUsersUser();
            _resultValue.accountStatus = accountStatus;
            _resultValue.adminRoles = adminRoles;
            _resultValue.areAllSchemasAccessible = areAllSchemasAccessible;
            _resultValue.authenticationType = authenticationType;
            _resultValue.key = key;
            _resultValue.schemaLists = schemaLists;
            _resultValue.targetId = targetId;
            _resultValue.timeLastLogin = timeLastLogin;
            _resultValue.timePasswordChanged = timePasswordChanged;
            _resultValue.timePasswordExpiry = timePasswordExpiry;
            _resultValue.timeUserCreated = timeUserCreated;
            _resultValue.userCategory = userCategory;
            _resultValue.userName = userName;
            _resultValue.userProfile = userProfile;
            _resultValue.userTypes = userTypes;
            return _resultValue;
        }
    }
}
