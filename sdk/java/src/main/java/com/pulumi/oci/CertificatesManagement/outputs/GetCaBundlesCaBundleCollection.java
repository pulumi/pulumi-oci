// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.CertificatesManagement.outputs.GetCaBundlesCaBundleCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetCaBundlesCaBundleCollection {
    private List<GetCaBundlesCaBundleCollectionItem> items;

    private GetCaBundlesCaBundleCollection() {}
    public List<GetCaBundlesCaBundleCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCaBundlesCaBundleCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetCaBundlesCaBundleCollectionItem> items;
        public Builder() {}
        public Builder(GetCaBundlesCaBundleCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetCaBundlesCaBundleCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetCaBundlesCaBundleCollectionItem... items) {
            return items(List.of(items));
        }
        public GetCaBundlesCaBundleCollection build() {
            final var o = new GetCaBundlesCaBundleCollection();
            o.items = items;
            return o;
        }
    }
}