// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabasesUserProxyUsersProxyUserCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagedDatabasesUserProxyUsersProxyUserCollection {
    /**
     * @return An array of user resources.
     * 
     */
    private List<GetManagedDatabasesUserProxyUsersProxyUserCollectionItem> items;

    private GetManagedDatabasesUserProxyUsersProxyUserCollection() {}
    /**
     * @return An array of user resources.
     * 
     */
    public List<GetManagedDatabasesUserProxyUsersProxyUserCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabasesUserProxyUsersProxyUserCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetManagedDatabasesUserProxyUsersProxyUserCollectionItem> items;
        public Builder() {}
        public Builder(GetManagedDatabasesUserProxyUsersProxyUserCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetManagedDatabasesUserProxyUsersProxyUserCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetManagedDatabasesUserProxyUsersProxyUserCollectionItem... items) {
            return items(List.of(items));
        }
        public GetManagedDatabasesUserProxyUsersProxyUserCollection build() {
            final var o = new GetManagedDatabasesUserProxyUsersProxyUserCollection();
            o.items = items;
            return o;
        }
    }
}