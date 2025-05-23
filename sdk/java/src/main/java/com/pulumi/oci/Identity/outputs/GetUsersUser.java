// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetUsersUserCapability;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetUsersUser {
    /**
     * @return Properties indicating how the user is allowed to authenticate.
     * 
     */
    private List<GetUsersUserCapability> capabilities;
    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    private String compartmentId;
    /**
     * @return DB username of the DB credential. Has to be unique across the tenancy.
     * 
     */
    private String dbUserName;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return The description you assign to the user. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    private String description;
    /**
     * @return The email address you assign to the user. The email address must be unique across all users in the tenancy.
     * 
     */
    private String email;
    /**
     * @return Whether the email address has been validated.
     * 
     */
    private Boolean emailVerified;
    /**
     * @return The id of a user in the identity provider.
     * 
     */
    private String externalIdentifier;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return The OCID of the user.
     * 
     */
    private String id;
    /**
     * @return The id of the identity provider.
     * 
     */
    private String identityProviderId;
    /**
     * @return Returned only if the user&#39;s `lifecycleState` is INACTIVE. A 16-bit value showing the reason why the user is inactive:
     * * bit 0: SUSPENDED (reserved for future use)
     * * bit 1: DISABLED (reserved for future use)
     * * bit 2: BLOCKED (the user has exceeded the maximum number of failed login attempts for the Console)
     * 
     */
    private String inactiveState;
    /**
     * @return The date and time of when the user most recently logged in the format defined by RFC3339 (ex. `2016-08-25T21:10:29.600Z`). If there is no login history, this field is null.
     * 
     */
    private String lastSuccessfulLoginTime;
    /**
     * @return A filter to only return resources that match the given name exactly.
     * 
     */
    private String name;
    /**
     * @return The date and time of when the user most recently logged in the format defined by RFC3339 (ex. `2016-08-25T21:10:29.600Z`). If there is no login history, this field is null.
     * 
     */
    private String previousSuccessfulLoginTime;
    /**
     * @return A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    private String state;
    /**
     * @return Date and time the user was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;

    private GetUsersUser() {}
    /**
     * @return Properties indicating how the user is allowed to authenticate.
     * 
     */
    public List<GetUsersUserCapability> capabilities() {
        return this.capabilities;
    }
    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return DB username of the DB credential. Has to be unique across the tenancy.
     * 
     */
    public String dbUserName() {
        return this.dbUserName;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The description you assign to the user. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return The email address you assign to the user. The email address must be unique across all users in the tenancy.
     * 
     */
    public String email() {
        return this.email;
    }
    /**
     * @return Whether the email address has been validated.
     * 
     */
    public Boolean emailVerified() {
        return this.emailVerified;
    }
    /**
     * @return The id of a user in the identity provider.
     * 
     */
    public String externalIdentifier() {
        return this.externalIdentifier;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return The OCID of the user.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The id of the identity provider.
     * 
     */
    public String identityProviderId() {
        return this.identityProviderId;
    }
    /**
     * @return Returned only if the user&#39;s `lifecycleState` is INACTIVE. A 16-bit value showing the reason why the user is inactive:
     * * bit 0: SUSPENDED (reserved for future use)
     * * bit 1: DISABLED (reserved for future use)
     * * bit 2: BLOCKED (the user has exceeded the maximum number of failed login attempts for the Console)
     * 
     */
    public String inactiveState() {
        return this.inactiveState;
    }
    /**
     * @return The date and time of when the user most recently logged in the format defined by RFC3339 (ex. `2016-08-25T21:10:29.600Z`). If there is no login history, this field is null.
     * 
     */
    public String lastSuccessfulLoginTime() {
        return this.lastSuccessfulLoginTime;
    }
    /**
     * @return A filter to only return resources that match the given name exactly.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The date and time of when the user most recently logged in the format defined by RFC3339 (ex. `2016-08-25T21:10:29.600Z`). If there is no login history, this field is null.
     * 
     */
    public String previousSuccessfulLoginTime() {
        return this.previousSuccessfulLoginTime;
    }
    /**
     * @return A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return Date and time the user was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetUsersUser defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetUsersUserCapability> capabilities;
        private String compartmentId;
        private String dbUserName;
        private Map<String,String> definedTags;
        private String description;
        private String email;
        private Boolean emailVerified;
        private String externalIdentifier;
        private Map<String,String> freeformTags;
        private String id;
        private String identityProviderId;
        private String inactiveState;
        private String lastSuccessfulLoginTime;
        private String name;
        private String previousSuccessfulLoginTime;
        private String state;
        private String timeCreated;
        public Builder() {}
        public Builder(GetUsersUser defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.capabilities = defaults.capabilities;
    	      this.compartmentId = defaults.compartmentId;
    	      this.dbUserName = defaults.dbUserName;
    	      this.definedTags = defaults.definedTags;
    	      this.description = defaults.description;
    	      this.email = defaults.email;
    	      this.emailVerified = defaults.emailVerified;
    	      this.externalIdentifier = defaults.externalIdentifier;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.identityProviderId = defaults.identityProviderId;
    	      this.inactiveState = defaults.inactiveState;
    	      this.lastSuccessfulLoginTime = defaults.lastSuccessfulLoginTime;
    	      this.name = defaults.name;
    	      this.previousSuccessfulLoginTime = defaults.previousSuccessfulLoginTime;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
        }

        @CustomType.Setter
        public Builder capabilities(List<GetUsersUserCapability> capabilities) {
            if (capabilities == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "capabilities");
            }
            this.capabilities = capabilities;
            return this;
        }
        public Builder capabilities(GetUsersUserCapability... capabilities) {
            return capabilities(List.of(capabilities));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder dbUserName(String dbUserName) {
            if (dbUserName == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "dbUserName");
            }
            this.dbUserName = dbUserName;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder description(String description) {
            if (description == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "description");
            }
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder email(String email) {
            if (email == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "email");
            }
            this.email = email;
            return this;
        }
        @CustomType.Setter
        public Builder emailVerified(Boolean emailVerified) {
            if (emailVerified == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "emailVerified");
            }
            this.emailVerified = emailVerified;
            return this;
        }
        @CustomType.Setter
        public Builder externalIdentifier(String externalIdentifier) {
            if (externalIdentifier == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "externalIdentifier");
            }
            this.externalIdentifier = externalIdentifier;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder identityProviderId(String identityProviderId) {
            if (identityProviderId == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "identityProviderId");
            }
            this.identityProviderId = identityProviderId;
            return this;
        }
        @CustomType.Setter
        public Builder inactiveState(String inactiveState) {
            if (inactiveState == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "inactiveState");
            }
            this.inactiveState = inactiveState;
            return this;
        }
        @CustomType.Setter
        public Builder lastSuccessfulLoginTime(String lastSuccessfulLoginTime) {
            if (lastSuccessfulLoginTime == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "lastSuccessfulLoginTime");
            }
            this.lastSuccessfulLoginTime = lastSuccessfulLoginTime;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder previousSuccessfulLoginTime(String previousSuccessfulLoginTime) {
            if (previousSuccessfulLoginTime == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "previousSuccessfulLoginTime");
            }
            this.previousSuccessfulLoginTime = previousSuccessfulLoginTime;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetUsersUser", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        public GetUsersUser build() {
            final var _resultValue = new GetUsersUser();
            _resultValue.capabilities = capabilities;
            _resultValue.compartmentId = compartmentId;
            _resultValue.dbUserName = dbUserName;
            _resultValue.definedTags = definedTags;
            _resultValue.description = description;
            _resultValue.email = email;
            _resultValue.emailVerified = emailVerified;
            _resultValue.externalIdentifier = externalIdentifier;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.identityProviderId = identityProviderId;
            _resultValue.inactiveState = inactiveState;
            _resultValue.lastSuccessfulLoginTime = lastSuccessfulLoginTime;
            _resultValue.name = name;
            _resultValue.previousSuccessfulLoginTime = previousSuccessfulLoginTime;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            return _resultValue;
        }
    }
}
