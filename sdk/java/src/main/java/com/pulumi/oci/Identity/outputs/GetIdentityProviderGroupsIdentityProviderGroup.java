// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
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
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder externalIdentifier(String externalIdentifier) {
            this.externalIdentifier = Objects.requireNonNull(externalIdentifier);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder identityProviderId(String identityProviderId) {
            this.identityProviderId = Objects.requireNonNull(identityProviderId);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeModified(String timeModified) {
            this.timeModified = Objects.requireNonNull(timeModified);
            return this;
        }
        public GetIdentityProviderGroupsIdentityProviderGroup build() {
            final var o = new GetIdentityProviderGroupsIdentityProviderGroup();
            o.displayName = displayName;
            o.externalIdentifier = externalIdentifier;
            o.id = id;
            o.identityProviderId = identityProviderId;
            o.name = name;
            o.timeCreated = timeCreated;
            o.timeModified = timeModified;
            return o;
        }
    }
}