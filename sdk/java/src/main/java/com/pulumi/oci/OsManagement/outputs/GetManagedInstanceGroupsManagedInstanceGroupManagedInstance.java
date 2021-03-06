// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedInstanceGroupsManagedInstanceGroupManagedInstance {
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable.  Example: `My new resource`
     * 
     */
    private final String displayName;
    /**
     * @return unique identifier that is immutable on creation
     * 
     */
    private final String id;

    @CustomType.Constructor
    private GetManagedInstanceGroupsManagedInstanceGroupManagedInstance(
        @CustomType.Parameter("displayName") String displayName,
        @CustomType.Parameter("id") String id) {
        this.displayName = displayName;
        this.id = id;
    }

    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable.  Example: `My new resource`
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return unique identifier that is immutable on creation
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedInstanceGroupsManagedInstanceGroupManagedInstance defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String displayName;
        private String id;

        public Builder() {
    	      // Empty
        }

        public Builder(GetManagedInstanceGroupsManagedInstanceGroupManagedInstance defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
        }

        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }        public GetManagedInstanceGroupsManagedInstanceGroupManagedInstance build() {
            return new GetManagedInstanceGroupsManagedInstanceGroupManagedInstance(displayName, id);
        }
    }
}
