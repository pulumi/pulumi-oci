// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataIntegration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetWorkspaceFoldersFolderSummaryCollectionItemParentRef {
    /**
     * @return Key of the parent object.
     * 
     */
    private String parent;
    /**
     * @return Key of the root document object.
     * 
     */
    private String rootDocId;

    private GetWorkspaceFoldersFolderSummaryCollectionItemParentRef() {}
    /**
     * @return Key of the parent object.
     * 
     */
    public String parent() {
        return this.parent;
    }
    /**
     * @return Key of the root document object.
     * 
     */
    public String rootDocId() {
        return this.rootDocId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWorkspaceFoldersFolderSummaryCollectionItemParentRef defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String parent;
        private String rootDocId;
        public Builder() {}
        public Builder(GetWorkspaceFoldersFolderSummaryCollectionItemParentRef defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.parent = defaults.parent;
    	      this.rootDocId = defaults.rootDocId;
        }

        @CustomType.Setter
        public Builder parent(String parent) {
            this.parent = Objects.requireNonNull(parent);
            return this;
        }
        @CustomType.Setter
        public Builder rootDocId(String rootDocId) {
            this.rootDocId = Objects.requireNonNull(rootDocId);
            return this;
        }
        public GetWorkspaceFoldersFolderSummaryCollectionItemParentRef build() {
            final var o = new GetWorkspaceFoldersFolderSummaryCollectionItemParentRef();
            o.parent = parent;
            o.rootDocId = rootDocId;
            return o;
        }
    }
}