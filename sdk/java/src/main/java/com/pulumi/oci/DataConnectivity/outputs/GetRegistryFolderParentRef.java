// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataConnectivity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetRegistryFolderParentRef {
    /**
     * @return Key of the parent object.
     * 
     */
    private String parent;

    private GetRegistryFolderParentRef() {}
    /**
     * @return Key of the parent object.
     * 
     */
    public String parent() {
        return this.parent;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRegistryFolderParentRef defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String parent;
        public Builder() {}
        public Builder(GetRegistryFolderParentRef defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.parent = defaults.parent;
        }

        @CustomType.Setter
        public Builder parent(String parent) {
            this.parent = Objects.requireNonNull(parent);
            return this;
        }
        public GetRegistryFolderParentRef build() {
            final var o = new GetRegistryFolderParentRef();
            o.parent = parent;
            return o;
        }
    }
}