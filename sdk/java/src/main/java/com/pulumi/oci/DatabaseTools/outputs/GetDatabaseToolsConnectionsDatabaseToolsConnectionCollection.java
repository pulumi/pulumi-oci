// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseTools.outputs.GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDatabaseToolsConnectionsDatabaseToolsConnectionCollection {
    private List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItem> items;

    private GetDatabaseToolsConnectionsDatabaseToolsConnectionCollection() {}
    public List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseToolsConnectionsDatabaseToolsConnectionCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItem> items;
        public Builder() {}
        public Builder(GetDatabaseToolsConnectionsDatabaseToolsConnectionCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetDatabaseToolsConnectionsDatabaseToolsConnectionCollectionItem... items) {
            return items(List.of(items));
        }
        public GetDatabaseToolsConnectionsDatabaseToolsConnectionCollection build() {
            final var o = new GetDatabaseToolsConnectionsDatabaseToolsConnectionCollection();
            o.items = items;
            return o;
        }
    }
}