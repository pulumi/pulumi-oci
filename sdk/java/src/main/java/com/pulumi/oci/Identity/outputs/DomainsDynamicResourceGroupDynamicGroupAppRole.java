// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsDynamicResourceGroupDynamicGroupAppRole {
    /**
     * @return (Updatable) If true, then the role provides administrative access privileges. READ-ONLY.
     * 
     */
    private @Nullable Boolean adminRole;
    /**
     * @return (Updatable) App identifier
     * 
     */
    private @Nullable String appId;
    /**
     * @return (Updatable) Name of parent App. READ-ONLY.
     * 
     */
    private @Nullable String appName;
    /**
     * @return (Updatable) The displayName of the User or App who modified this Resource
     * 
     */
    private @Nullable String display;
    /**
     * @return (Updatable) The name of the legacy group associated with this AppRole.
     * 
     */
    private @Nullable String legacyGroupName;
    /**
     * @return (Updatable) The URI of the SCIM resource that represents the User or App who modified this Resource
     * 
     */
    private @Nullable String ref;
    /**
     * @return (Updatable) Oracle Cloud Infrastructure Tag value
     * 
     */
    private String value;

    private DomainsDynamicResourceGroupDynamicGroupAppRole() {}
    /**
     * @return (Updatable) If true, then the role provides administrative access privileges. READ-ONLY.
     * 
     */
    public Optional<Boolean> adminRole() {
        return Optional.ofNullable(this.adminRole);
    }
    /**
     * @return (Updatable) App identifier
     * 
     */
    public Optional<String> appId() {
        return Optional.ofNullable(this.appId);
    }
    /**
     * @return (Updatable) Name of parent App. READ-ONLY.
     * 
     */
    public Optional<String> appName() {
        return Optional.ofNullable(this.appName);
    }
    /**
     * @return (Updatable) The displayName of the User or App who modified this Resource
     * 
     */
    public Optional<String> display() {
        return Optional.ofNullable(this.display);
    }
    /**
     * @return (Updatable) The name of the legacy group associated with this AppRole.
     * 
     */
    public Optional<String> legacyGroupName() {
        return Optional.ofNullable(this.legacyGroupName);
    }
    /**
     * @return (Updatable) The URI of the SCIM resource that represents the User or App who modified this Resource
     * 
     */
    public Optional<String> ref() {
        return Optional.ofNullable(this.ref);
    }
    /**
     * @return (Updatable) Oracle Cloud Infrastructure Tag value
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsDynamicResourceGroupDynamicGroupAppRole defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean adminRole;
        private @Nullable String appId;
        private @Nullable String appName;
        private @Nullable String display;
        private @Nullable String legacyGroupName;
        private @Nullable String ref;
        private String value;
        public Builder() {}
        public Builder(DomainsDynamicResourceGroupDynamicGroupAppRole defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adminRole = defaults.adminRole;
    	      this.appId = defaults.appId;
    	      this.appName = defaults.appName;
    	      this.display = defaults.display;
    	      this.legacyGroupName = defaults.legacyGroupName;
    	      this.ref = defaults.ref;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder adminRole(@Nullable Boolean adminRole) {
            this.adminRole = adminRole;
            return this;
        }
        @CustomType.Setter
        public Builder appId(@Nullable String appId) {
            this.appId = appId;
            return this;
        }
        @CustomType.Setter
        public Builder appName(@Nullable String appName) {
            this.appName = appName;
            return this;
        }
        @CustomType.Setter
        public Builder display(@Nullable String display) {
            this.display = display;
            return this;
        }
        @CustomType.Setter
        public Builder legacyGroupName(@Nullable String legacyGroupName) {
            this.legacyGroupName = legacyGroupName;
            return this;
        }
        @CustomType.Setter
        public Builder ref(@Nullable String ref) {
            this.ref = ref;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public DomainsDynamicResourceGroupDynamicGroupAppRole build() {
            final var o = new DomainsDynamicResourceGroupDynamicGroupAppRole();
            o.adminRole = adminRole;
            o.appId = appId;
            o.appName = appName;
            o.display = display;
            o.legacyGroupName = legacyGroupName;
            o.ref = ref;
            o.value = value;
            return o;
        }
    }
}