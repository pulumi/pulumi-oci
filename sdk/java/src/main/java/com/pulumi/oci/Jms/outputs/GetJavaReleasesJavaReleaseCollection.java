// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Jms.outputs.GetJavaReleasesJavaReleaseCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetJavaReleasesJavaReleaseCollection {
    private List<GetJavaReleasesJavaReleaseCollectionItem> items;

    private GetJavaReleasesJavaReleaseCollection() {}
    public List<GetJavaReleasesJavaReleaseCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetJavaReleasesJavaReleaseCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetJavaReleasesJavaReleaseCollectionItem> items;
        public Builder() {}
        public Builder(GetJavaReleasesJavaReleaseCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetJavaReleasesJavaReleaseCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetJavaReleasesJavaReleaseCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetJavaReleasesJavaReleaseCollectionItem... items) {
            return items(List.of(items));
        }
        public GetJavaReleasesJavaReleaseCollection build() {
            final var _resultValue = new GetJavaReleasesJavaReleaseCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
