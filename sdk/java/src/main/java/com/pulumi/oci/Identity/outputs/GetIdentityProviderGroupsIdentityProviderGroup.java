// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetIdentityProviderGroupsIdentityProviderGroup {
    /**
     * @return Display name of the group
     * 
     */
    private String displayName;
    /**
     * @return Identifier of the group in the identity provider
     * 
     */
    private String externalIdentifier;
    /**
     * @return The OCID of the `IdentityProviderGroup`.
     * 
     */
    private String id;
    /**
     * @return The OCID of the identity provider.
     * 
     */
    private String identityProviderId;
    /**
     * @return A filter to only return resources that match the given name exactly.
     * 
     */
    private String name;
    /**
     * @return Date and time the `IdentityProviderGroup` was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return Date and time the `IdentityProviderGroup` was last modified, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeModified;

    private GetIdentityProviderGroupsIdentityProviderGroup() {}
    /**
     * @return Display name of the group
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Identifier of the group in the identity provider
     * 
     */
    public String externalIdentifier() {
        return this.externalIdentifier;
    }
    /**
     * @return The OCID of the `IdentityProviderGroup`.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The OCID of the identity provider.
     * 
     */
    public String identityProviderId() {
        return this.identityProviderId;
    }
    /**
     * @return A filter to only return resources that match the given name exactly.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Date and time the `IdentityProviderGroup` was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Date and time the `IdentityProviderGroup` was last modified, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeModified() {
        return this.timeModified;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIdentityProviderGroupsIdentityProviderGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String displayName;
        private String externalIdentifier;
        private String id;
        private String identityProviderId;
        private String name;
        private String timeCreated;
        private String timeModified;
        public Builder() {}
        public Builder(GetIdentityProviderGroupsIdentityProviderGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.externalIdentifier = defaults.externalIdentifier;
    	      this.id = defaults.id;
    	      this.identityProviderId = defaults.identityProviderId;
    	      this.name = defaults.name;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeModified = defaults.timeModified;
        }

        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetIdentityProviderGroupsIdentityProviderGroup", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder externalIdentifier(String externalIdentifier) {
            if (externalIdentifier == null) {
              throw new MissingRequiredPropertyException("GetIdentityProviderGroupsIdentityProviderGroup", "externalIdentifier");
            }
            this.externalIdentifier = externalIdentifier;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetIdentityProviderGroupsIdentityProviderGroup", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder identityProviderId(String identityProviderId) {
            if (identityProviderId == null) {
              throw new MissingRequiredPropertyException("GetIdentityProviderGroupsIdentityProviderGroup", "identityProviderId");
            }
            this.identityProviderId = identityProviderId;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetIdentityProviderGroupsIdentityProviderGroup", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetIdentityProviderGroupsIdentityProviderGroup", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeModified(String timeModified) {
            if (timeModified == null) {
              throw new MissingRequiredPropertyException("GetIdentityProviderGroupsIdentityProviderGroup", "timeModified");
            }
            this.timeModified = timeModified;
            return this;
        }
        public GetIdentityProviderGroupsIdentityProviderGroup build() {
            final var _resultValue = new GetIdentityProviderGroupsIdentityProviderGroup();
            _resultValue.displayName = displayName;
            _resultValue.externalIdentifier = externalIdentifier;
            _resultValue.id = id;
            _resultValue.identityProviderId = identityProviderId;
            _resultValue.name = name;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeModified = timeModified;
            return _resultValue;
        }
    }
}
