// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedInstanceManagedInstanceGroup {
    /**
     * @return User friendly name
     * 
     */
    private String displayName;
    /**
     * @return software source identifier
     * 
     */
    private String id;

    private GetManagedInstanceManagedInstanceGroup() {}
    /**
     * @return User friendly name
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return software source identifier
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedInstanceManagedInstanceGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String displayName;
        private String id;
        public Builder() {}
        public Builder(GetManagedInstanceManagedInstanceGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public GetManagedInstanceManagedInstanceGroup build() {
            final var o = new GetManagedInstanceManagedInstanceGroup();
            o.displayName = displayName;
            o.id = id;
            return o;
        }
    }
}